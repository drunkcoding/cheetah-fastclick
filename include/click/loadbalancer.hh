// -*- c-basic-offset: 4 -*-
#ifndef CLICK_LB_HH
#define CLICK_LB_HH

#include <click/ipflowid.hh>
#include <algorithm>
#include <click/dpdk_glue.hh>
#include <click/hashtable.hh>
#include <click/ring.hh>
#include <click/multithread.hh>
#include <click/args.hh>
#include <click/straccum.hh>
#include <chrono>
#include <math.h>

typedef std::chrono::steady_clock Clock;
typedef std::chrono::steady_clock::time_point TimePoint;
typedef std::chrono::duration<double> DurationSeconds;

#define BUF_SIZE 0x1000

class LoadBalancer { public:

    LoadBalancer() : _current(0),  _dsts(), _weights_helper(), _mode_case(round_robin) {
        modetrans.find_insert("rr",round_robin);
        modetrans.find_insert("tr",training);
        modetrans.find_insert("single",single_backend);
        modetrans.find_insert("est_avg", average_estimation);
        modetrans.find_insert("est_least", least_estimation);
        modetrans.find_insert("est_stat", statistical_estimation);
        modetrans.find_insert("hash",direct_hash);
        modetrans.find_insert("hash_crc",direct_hash_crc);
        modetrans.find_insert("hash_agg",direct_hash_agg);
        modetrans.find_insert("cst_hash_agg",constant_hash_agg);
        modetrans.find_insert("wrr",weighted_round_robin);
        modetrans.find_insert("awrr",auto_weighted_round_robin);
        modetrans.find_insert("least",least_load);
        modetrans.find_insert("pow2",pow2);
        lsttrans.find_insert("conn",connections);
        lsttrans.find_insert("packets",packets);
        lsttrans.find_insert("bytes",bytes);
        lsttrans.find_insert("cpu",cpu);
    }

    enum LBMode {
        round_robin,
        training,
        single_backend,
        average_estimation,
        least_estimation,
        statistical_estimation,
        weighted_round_robin,
        auto_weighted_round_robin,
        pow2,
        constant_hash_agg,
        direct_hash,
        direct_hash_crc,
        direct_hash_agg,
        least_load
    };

    static bool isLoadBased(LBMode mode) {
        return mode == pow2 || mode == least_load || mode == weighted_round_robin  || mode == auto_weighted_round_robin 
        || mode == training || mode == average_estimation || mode == least_estimation || mode == statistical_estimation;
    }

    enum LSTMode {
        connections,
        packets,
        bytes,
        cpu
    };

    typedef atomic_uint64_t load_type_t;

    struct load {
        load() {
            connection_load = 0;
            cpu_load = 0;
            packets_load = 0;
            bytes_load = 0;
        }
        load_type_t connection_load;
        load_type_t packets_load;
        load_type_t bytes_load;
        uint64_t cpu_load;
    } CLICK_CACHE_ALIGN;

    // for numerical value estimation
    template <typename T, size_t RING_SIZE = BUF_SIZE>
    struct estimate_element {
        estimate_element() {
            access = Clock::now();
            sum = 0;
        }
        void insert(T val) {
            sum += val;
            bool is_success = buf.insert(val);
            if (!is_success) {
                auto old_val = buf.extract();
                buf.insert(val);
                sum -= old_val;
            }
        }
        T mean() { return (buf.count() == 0)? -1 : sum / buf.count(); }
        T std() { 
            if (buf.count() == 0) return -1;
            T s = 0, m = mean();
            for (int j = buf.tail; j < buf.head; j++) {
                s += pow(buf.ring[j % RING_SIZE]-m,2);
            }
            return sqrt(s/buf.count());
        }
        Ring<T, RING_SIZE> buf;
        TimePoint access;
        T sum;
    } CLICK_CACHE_ALIGN;

    struct estimate {
        estimate() {
            pick_time = Clock::now();
        }
        estimate_element<double> bw_est;
        estimate_element<double> tps_est;
        estimate_element<double> conn_est;
        Vector<double> cpu_hist;
        TimePoint pick_time;
    } CLICK_CACHE_ALIGN;

    std::chrono::steady_clock::time_point _batch_time = std::chrono::steady_clock::now();


protected:
    HashTable<String, LBMode> modetrans;
    HashTable<String, LSTMode> lsttrans;
    per_thread<int> _current;
    Vector <IPAddress> _dsts;
    unprotected_rcu_singlewriter<Vector <unsigned>,2> _weights_helper;
    LBMode _mode_case;
    LSTMode _lst_case;
    Vector <load,CLICK_CACHE_LINE_SIZE> _loads;
    Vector <load,CLICK_CACHE_LINE_SIZE> _last_loads;
    Vector <double> _pre_loads;
    Vector <estimate> _est_loads;
    Vector <unsigned> _selector;
    Vector <unsigned> _cst_hash;
    Vector <unsigned> _spares;
    bool _track_load;
    bool _force_track_load;
    int _awrr_interval;
    float _alpha;
    bool _autoscale;

    uint64_t get_load_metric(int idx) {
    return get_load_metric(idx, _lst_case);
    }
    uint64_t get_load_metric(int idx,LSTMode metric) {
        load& l = _loads[idx];
        switch(metric) {
            case connections: {
                return l.connection_load;
            }
            case bytes: {
                return l.bytes_load;
            }
            case packets: {
                return l.packets_load;
            }
            case cpu: {
                return l.cpu_load;
            }
            default:
                assert(false);
        }
    }

    unsigned cantor(unsigned a, unsigned b) {
        return ((a + b)  * (a + b + 1))/2 + b;
    }

    void build_hash_ring() {
        Vector<unsigned> new_hash;
        new_hash.resize(_cst_hash.size(), -1);
        int fac = ((new_hash.size() - 1) / _selector.size()) + 1;
        for (int j = 0; j < fac; j++) {
            for (int i = 0; i < _selector.size(); i++) {
                int server_place = cantor(_selector[i], j) % new_hash.size();
                new_hash[server_place] = _selector[i];
            }

        }
        int cur = _selector[0];
        for (int i = 0; i < new_hash.size(); i++) {
            if (new_hash[i] == - 1) {
                new_hash[i] = cur;
            } else
                cur = new_hash[i];
        }
        _cst_hash.swap(new_hash);
    }

    static void atc(Timer *timer, void *user_data) {
        LoadBalancer* lb = (LoadBalancer*)user_data;
        uint64_t metric_tot = 0;
        for (int i = 0; i < lb->_loads.size(); i++) {
            metric_tot += lb->get_load_metric(i);
        }
        uint64_t avg = metric_tot / lb->_dsts.size();

        Vector<unsigned> new_weight;
        for (int i = 0; i < lb->_dsts.size(); i++) {
                float l = lb->get_load_metric(i);
                /**
                 *Examples:
                 * Average is 50. Load of this core is 80.
                 * a=-1 -> 10*50 / 160 - 50 = 4,5
                 * Load is 30.
                 * a=0 -> 10 * 50 / 30 = 17
                 * a=-1 -> 10 * 50 / 10 = 5
                 * Load is 50
                 * a=-1 -> 10 *50 / 2*50 - 50 = 10
                 */
                float buckets;
                if (l == 0) {
                    buckets = 30;
                } else {
                buckets = 10 * avg / ((1 - lb->_alpha) * l + lb->_alpha*avg);
                if (buckets > 30) buckets = 30;
                else if (buckets < 2) buckets = 2;
                }
                new_weight.push_back((unsigned)buckets);
               // click_chatter("%d load %f,  %d buck",i,l,(unsigned)buckets);
        }
        lb->set_weights(new_weight.data());
        timer->reschedule_after_msec(lb->_awrr_interval);
    }

    int parseLb(Vector<String> &conf, Element* lb, ErrorHandler* errh) {
        String lb_mode;
        String lst_mode;
        int awrr_timer;
        double alpha;
        bool autoscale;
        bool has_cst_buckets;
        int cst_buckets;
        int nserver;
        bool force_track_load;
        int ret = Args(lb, errh).bind(conf)
            .read_or_set("LB_MODE", lb_mode,"rr")
            .read_or_set("LST_MODE",lst_mode,"conn")
            .read_or_set("AWRR_TIME",awrr_timer, 100)
            .read_or_set("AUTOSCALE", autoscale, false)
            .read_or_set("FORCE_TRACK_LOAD", force_track_load, false)
            .read_or_set("NSERVER", nserver, 0)
            .read("CST_BUCKETS", cst_buckets).read_status(has_cst_buckets)
            .read_or_set("AWRR_ALPHA", alpha, 0).consume();

        if (ret < 0)
            return -1;

        _alpha = alpha;
        _autoscale = autoscale;
        _force_track_load = force_track_load;
        if (has_cst_buckets) {
            _cst_hash.resize(cst_buckets, -1);
        }

        set_mode(lb_mode, lst_mode, lb, awrr_timer, nserver);

        return ret;
    }

    void add_server() {
        if (_spares.size() == 0) {
            click_chatter("No server to add!");
            return;
        }
        int spare = _spares.front();
        _spares.pop_front();

        int id = click_random() % _selector.size();
        Vector<unsigned> news;
        news.reserve(_dsts.size());
        for (int i = 0; i < _selector.size(); i++) {
            if (i == id) {
                news.push_back(spare);
            }
            news.push_back(_selector[i]);
        }
        _selector.swap(news);
        if (_mode_case == constant_hash_agg) {
            build_hash_ring();
        }
    }

    void remove_server() {
        if (_selector.size() == 0) {
            click_chatter("No server to remove!");
            return;
        }

        int id = click_random() % _selector.size();
        int removed = _selector[id];
        Vector<unsigned> news;
        news.reserve(_dsts.size());
        for (int i = 0; i < _selector.size(); i++) {
            if (i == id) {
                continue;
            }
            news.push_back(_selector[i]);
        }
        _spares.push_back(removed);
        _selector.swap(news);
        if (_mode_case == constant_hash_agg) {
            build_hash_ring();
        }
    }

    enum {
            h_load,h_nb_total_servers,h_nb_active_servers,h_load_conn,h_load_packets,h_load_bytes,h_add_server,h_remove_server
    };


    int lb_handler(int op, String &data, void *r_thunk, void* w_thunk, ErrorHandler *errh) {

        LoadBalancer *cs = this;
        if (op == Handler::f_read) {
            switch((uintptr_t) r_thunk) {
            case h_load: {
                    StringAccum acc;
                    if (data) {
                        int i = atoi(data.c_str());
                        if (cs->_loads.size() <= i) {
                            acc << "unknown";
                        } else {
                            acc << cs->_loads[i].cpu_load ;
                        }
                    } else {
                        for (int i = 0; i < cs->_dsts.size(); i ++) {
                            if (cs->_loads.size() <= i) {
                                acc << "unknown";
                            } else {
                                acc << cs->_loads[i].cpu_load ;
                            }
                            acc << (i == cs->_dsts.size() -1?"":" ");
                        }
                    }
                    data = acc.take_string();
                    return 0;
                }
            }
        } else {
        switch((uintptr_t)w_thunk) {
                case h_load: {
                    String s(data);
                    while (s.length() > 0) {
                        int ntoken = s.find_left(',');
                        if (ntoken < 0)
                            ntoken = s.length() - 1;
                        int pos = s.find_left(':');
                        int server_id = atoi(s.substring(0,pos).c_str());
                        int server_load = atoi(s.substring(pos + 1, ntoken).c_str());
                        //click_chatter("%d is %d",server_id, server_load);
                        if (cs->_loads.size() <= server_id) {
                            click_chatter("Invalid server id %d", server_id);
                            return 1;
                        }
                        cs->_est_loads[server_id].cpu_hist.push_back(server_load);
                        cs->_loads[server_id].cpu_load = server_load;
                        s = s.substring(ntoken + 1);
                    }
                    if (cs->_autoscale)
                    cs->checkload();
                    return 0;
                }
            }
        }
    }



    int lb_write_handler(
            const String &input, void *thunk, ErrorHandler *errh) {
        LoadBalancer *cs = this;
        switch((uintptr_t) thunk) {
            case h_add_server: {
                add_server();
                break;
            }
            case h_remove_server: {
                remove_server();
                break;
            }
        }
        return -1;
    }

    String
    lb_read_handler(void *thunk) {
        LoadBalancer *cs = this;

        switch((uintptr_t) thunk) {
            case h_nb_active_servers: {
               return String(cs->_selector.size());
            }
            case h_nb_total_servers: {
                return String(cs->_dsts.size());
            }

            case h_load_conn: {
                StringAccum acc;
                for (int i = 0; i < cs->_dsts.size(); i ++) {
                    acc << cs->get_load_metric(i,connections) << (i == cs->_dsts.size() -1?"":" ");
                }
                return acc.take_string();}
            case h_load_packets:{
                StringAccum acc;
                for (int i = 0; i < cs->_dsts.size(); i ++) {
                    acc << cs->get_load_metric(i,packets) << (i == cs->_dsts.size() -1?"":" ");
                }
                return acc.take_string();}
            case h_load_bytes:{
                StringAccum acc;
                for (int i = 0; i <cs-> _dsts.size(); i ++) {
                    acc << cs->get_load_metric(i,bytes) << (i == cs->_dsts.size() -1?"":" ");
                }
                return acc.take_string();}
            default:
                return "<none>";
        }
    }



    void checkload() {
        double tot = 0;
        for (int i = 0; i < _selector.size(); i++) {
            tot += _loads[_selector[i]].cpu_load;
        }
        double avg = tot / _loads.size();
        if (avg > 80 && _spares.size() > 0) {
            click_chatter("Load is %f, adding a server", avg);
            add_server();
        } else if (avg < 40 && _selector.size() > 1) {
            remove_server();
            click_chatter("Load is %f, removing a server", avg);
        }

    }

    void set_mode(String mode, String metric="cpu", Element* owner=0,int awrr_timer_interval = -1, int nserver = 0) {
        auto item = modetrans.find(mode);
        _mode_case = item.value();
        if (_mode_case == weighted_round_robin || _mode_case == auto_weighted_round_robin) {
            auto &wh = _weights_helper.write_begin();
            wh.resize(_dsts.size());
            for(int i=0; i<_dsts.size(); i++) {
                wh[i] = i;
            }
            _weights_helper.write_commit();
        }

        _lst_case = lsttrans.find(metric).value();
        _track_load = ((isLoadBased(_mode_case)) && _lst_case != cpu) || _force_track_load;

        if (_mode_case == auto_weighted_round_robin) {
            Timer* awrr_timer = new Timer(atc, this);
            awrr_timer->initialize(owner, false);
            _awrr_interval = awrr_timer_interval;
            awrr_timer->schedule_after(Timestamp::make_msec(_awrr_interval));
        }

        if (nserver == 0) {
            if (_autoscale) {
                nserver=1;
            } else {
                nserver= _dsts.size();
            }
        }

        if (_mode_case == round_robin ||_mode_case == weighted_round_robin || _mode_case == auto_weighted_round_robin) {
            int p = nserver / _current.weight();
            if (p == 0)
                p = 1;
            for (int i = 0; i < _current.weight(); i++) {
                _current.get_value(i) = (i * p) % nserver;
            }
        }
        _spares.reserve(_dsts.size());
        _selector.reserve(_dsts.size());
        for (int i = nserver; i < _dsts.size(); i++)
            _spares.push_back(i);
        for (int i = 0; i < nserver; i++)
            _selector.push_back(i);

        if (_mode_case == constant_hash_agg) {
            if (_cst_hash.size() == 0)
                _cst_hash.resize(_dsts.size() * 100);
            build_hash_ring();
        }

        _loads.resize(_dsts.size());
        CLICK_ASSERT_ALIGNED(_loads.data());

        _last_loads.resize(_dsts.size());
        CLICK_ASSERT_ALIGNED(_last_loads.data());

        _est_loads.resize(_dsts.size());

        _pre_loads.resize(_dsts.size());
        for (int i = 0; i < _dsts.size(); i++) _pre_loads[i] = 0;
        //CLICK_ASSERT_ALIGNED(_pre_loads.data());
        // 
    }

    void set_weights(unsigned weigths_value[]) {
        Vector<unsigned> weights_helper;
        for(int i=0; i<_dsts.size(); i++) {
            for (unsigned j=0; j<weigths_value[i]; j++) {
                weights_helper.push_back(i);
            }
        }
        std::random_shuffle(weights_helper.begin(), weights_helper.end());
        auto& v = _weights_helper.write_begin();
        v = weights_helper;
        _weights_helper.write_commit();
    }

    inline double get_ARIMA(int sid, int n) {
        auto& cpu_hist = _est_loads[sid].cpu_hist;
        size_t obs_size = cpu_hist.size()-1;
        size_t ar_size = 3, ma_size= 2;
        double ma_params[ma_size] = {0.8399, 0.0213};
        double ar_params[ar_size] = {1.0248, 0.4380, -0.4785};
        double intercept = 22.7277;
        Vector<double> win;
        
        for (size_t i = 1; i < cpu_hist.size(); i++) win.push_back(cpu_hist[i]-cpu_hist[i-1]);

        // Initialize error values
        Vector<double> errors;
        for (int i = 0; i<2; i++) errors.push_back(0.0);

        // Create whole window of values: observed + predicted
        for (size_t i=0; i < n; i++) win.push_back(0.0);

        // Make predictions when q > 0
        for (size_t i=ar_size; i < win.size(); i++) {

            double new_val = 0;
            double error_now = 0;
            double phi_factor = 1.0;

            // Do the AR part
            for (size_t j=0; j < ar_size; j++) {
                new_val += ar_params[j] * win[i-1-j];
                phi_factor -= ar_params[j];
            }

            // Do the MA part
            for (unsigned int j=0; j < ma_size; j++)
                new_val += ma_params[j] * errors[ma_size-1-j];

            // Add intersect
            new_val += intercept * phi_factor;

            // Update predictions
            if (i >= obs_size) {
                win[i] = new_val;
                error_now = 0;
            } else {
                error_now = win[i] - new_val;
            }

            // Update errors
            for (size_t i=0; i < ma_size - 1; i++)
                errors[i] = errors[i+1];

            errors[ma_size-1] = error_now;
        }

        // Update prediction structure
        return abs(win[win.size()-1]);
    }

    inline int pick_server(const Packet* p) {
        switch(_mode_case) {
            case single_backend : {
                // for benchmarking purpose, only send to single backend
                return 0;
            }
            case average_estimation: {
                double avg_conn_bw = 0, avg_conn_time = 0, avg_conn_tps = 0;

                std::function<bool(double,double)> comp = [&](double m,double n)-> bool {return m<n;};
                auto result = std::min_element(std::begin(_pre_loads), std::end(_pre_loads),comp);
                int sid = std::distance(std::begin(_pre_loads), result);
                
                for (auto& est : _est_loads) {
                    avg_conn_bw += (est.bw_est.buf.count() == 0)? 0 : est.bw_est.sum / est.bw_est.buf.count();
                    avg_conn_time += (est.conn_est.buf.count() == 0)? 0 : est.conn_est.sum / est.conn_est.buf.count();
                    avg_conn_tps += (est.tps_est.buf.count() == 0)? 0 : est.tps_est.sum / est.tps_est.buf.count();
                }
                avg_conn_bw /= _est_loads.size();
                avg_conn_time /= _est_loads.size();
                avg_conn_tps /= _est_loads.size();

                click_chatter("avg_conn_bw %lf, avg_conn_time %lf, avg_conn_tps %lf", avg_conn_bw,  avg_conn_time, avg_conn_tps);
                for (int i = 0; i < _pre_loads.size(); i++)  click_chatter("%d _pre_loads %lf", i, _pre_loads[i]);

                

                switch(_lst_case) {
                        case bytes: {
                            _pre_loads[sid] = _pre_loads[sid] + avg_conn_bw*avg_conn_time;
                            break;
                        }
                        case packets: {
                            _pre_loads[sid] = _pre_loads[sid] + avg_conn_tps*avg_conn_time;
                            break;
                        }
                        case connections: {
                            _pre_loads[sid] = _pre_loads[sid] + avg_conn_time;
                            break;
                        }
                        default:
                            assert(false);
                            break;
                    }

                return sid;
            }
            case least_estimation: {
                double min_est = 1e100;
                int idx = 0;
                auto now = Clock::now();
                for (int i = 0; i < _dsts.size(); i++) {
                    DurationSeconds d = now - _est_loads[i].pick_time;
                    double bw_est = (_loads[i].bytes_load-_last_loads[i].bytes_load)/d.count();
                    double iops_est = (_loads[i].packets_load-_last_loads[i].packets_load)/d.count();
                    double cpu_est = _loads[i].cpu_load * pow(0.995, d.count()*1000) 
                        + (_loads[i].packets_load-_last_loads[i].packets_load) * 0.05;
                    switch(_lst_case) {
                        case bytes: {
                            if (bw_est < min_est) {
                                min_est = bw_est;
                                idx = i;
                            }
                            break;
                        }
                        case packets: {
                            if (iops_est < min_est) {
                                min_est = iops_est;
                                idx = i;
                            }
                            break;
                        }
                        case cpu: {
                            if (cpu_est < min_est) {
                                min_est = cpu_est;
                                idx = i;
                            }
                            break;
                        }
                        default:
                            if (iops_est*bw_est < min_est) {
                                min_est = iops_est*bw_est;
                                idx = i;
                            }
                            break;
                    }
                    _last_loads[i] = _loads[i];
                    _est_loads[i].pick_time = now;
                }

                // click_chatter("%d min_est %lf", idx, min_est);
                return idx;
            }
            case statistical_estimation: {
                double min_est = 1e100;
                int idx = 0;
                double avg_conn_time = 0;
                for (auto& est : _est_loads) {
                    avg_conn_time += (est.conn_est.buf.count() == 0)? 0 : est.conn_est.sum / est.conn_est.buf.count();
                }
                avg_conn_time /= _est_loads.size();
                int n = ceil(avg_conn_time*10);
                for (int i = 0; i < _dsts.size(); i++) {
                    auto& est = _est_loads[i];
                    if (est.cpu_hist.size() < 10) {
                        int b = _selector.unchecked_at((*_current)++);
                        if (*_current == (unsigned)_selector.size()) {
                            *_current = 0;
                        }
                        return b;
                    }
                    double pred = get_ARIMA(i,n);
                    click_chatter("%d pred %lf, %d", i, pred, n);
                    if (pred < min_est) {
                        min_est = pred;
                        idx = i;
                    }
                }
                return idx;
            }
            /*
            case least_estimation: {
                double min_est = 1e100;
                int idx = 0;
                auto now = Clock::now();
                for (int i = 0; i < _dsts.size(); i++) {
                    DurationSeconds d = now - _est_loads[i].pick_time;
                    // double bw_est = (_loads[i].bytes_load-_last_loads[i].bytes_load)/d.count();
                    double avg_conn_bw = 0, avg_conn_time = 0;
                    for (auto& est : _est_loads) {
                        avg_conn_bw += (est.bw_est.buf.count() == 0)? 0 : est.bw_est.sum / est.bw_est.buf.count();
                        avg_conn_time += (est.conn_est.buf.count() == 0)? 0 : est.conn_est.sum / est.conn_est.buf.count();
                    }
                    avg_conn_bw /= _est_loads.size();
                    avg_conn_time /= _est_loads.size();
                    double bw_est = 0, max_est = 0;
                    for (int j = _est_loads[i].bw_est.buf.tail; j < _est_loads[i].bw_est.buf.head; j++) {
                        bw_est = 0.35*bw_est + 0.65*_est_loads[i].bw_est.buf.ring[j % BUF_SIZE];
                    }
                    //for (int j = 0; j < int(avg_conn_time*100000); j++) {
                    bw_est = 0.25*bw_est + 0.75*avg_conn_bw;
                    //}

                    double tps_est = (_est_loads[i].tps_est.buf.count() == 0)? 0 : _est_loads[i].tps_est.sum / _est_loads[i].tps_est.buf.count();
                    double cpu_est = _loads[i].cpu_load * pow(0.995, d.count()*1000)
                        + tps_est * d.count()
                        + (_est_loads[i].conn_est.buf.count() == 0)? 0 : (_est_loads[i].conn_est.sum / _est_loads[i].conn_est.buf.count())*tps_est;
                    click_chatter("bw_est %lf, tps_est %lf, cpu_est %lf", bw_est,  tps_est, cpu_est);
                    switch(_lst_case) {
                        case bytes: {
                            if (bw_est < min_est) {
                                min_est = bw_est;
                                idx = i;
                            }
                            break;
                        }
                        case packets: {
                            if (tps_est < min_est) {
                                min_est = tps_est;
                                idx = i;
                            }
                            break;
                        }
                        case cpu: {
                            if (cpu_est < min_est) {
                                min_est = cpu_est;
                                idx = i;
                            }
                            break;
                        }
                        default:
                            if (tps_est*bw_est < min_est) {
                                min_est = tps_est*bw_est;
                                idx = i;
                            }
                            break;
                    }
                }
                _last_loads[idx] = _loads[idx];
                if (_lst_case != cpu) _est_loads[idx].pick_time = now;
                return idx;
            }
            */
            case round_robin: {
                int b = _selector.unchecked_at((*_current)++);
                if (*_current == (unsigned)_selector.size()) {
                    *_current = 0;
                }
                return b;
            }
            case direct_hash_crc: {
                IPFlow5ID srv = IPFlow5ID(p);
                unsigned server_val = ipv4_hash_crc(&srv, sizeof(srv), 0);
                server_val = ((server_val >> 16) ^ (server_val & 65535)) % _selector.size();
                return _selector.unchecked_at(server_val);
            }
            case direct_hash_agg: {
                unsigned server_val = AGGREGATE_ANNO(p);
                server_val = ((server_val >> 16) ^ (server_val & 65535)) % _selector.size();
                return _selector.unchecked_at(server_val);
            }
            case direct_hash: {
                unsigned server_val = IPFlowID(p, false).hashcode();
                server_val = ((server_val >> 16) ^ (server_val & 65535)) % _selector.size();
                return _selector.unchecked_at(server_val);
            }
            case constant_hash_agg: {
                unsigned server_val = AGGREGATE_ANNO(p);
                server_val = ((server_val >> 16) ^ (server_val & 65535)) % _cst_hash.size();
                return _cst_hash.unchecked_at(server_val);
            }
            case auto_weighted_round_robin:
            case weighted_round_robin: {
                //click_chatter("weighted Round Robin mode");
                auto & wh = _weights_helper.read_begin();
                int b = (*_current)++;
                if (*_current >= wh.size())
                    *_current = 0;
                if (b >= wh.size()) //Upon WR change, this may be over the new limit
                    b = 0;

                int server = wh.unchecked_at(b);
                _weights_helper.read_end();
                return server;
            }
            case least_load: {
                //click_chatter("Least loaded mode");
                std::function<bool(load,load)> comp;

                switch(_lst_case) {
                    case connections: {
                        comp = [&](load m,load n)-> bool {return m.connection_load<n.connection_load;};
                        break;
                    }
                    case bytes: {
                        comp = [&](load m,load n)-> bool {return m.bytes_load<n.bytes_load;};
                        break;
                    }
                    case packets: {
                        comp = [&](load m,load n)-> bool {return m.packets_load<n.packets_load;};
                        break;
                    }
                    case cpu: {
                        comp = [&](load m,load n)-> bool {return m.cpu_load<n.cpu_load;};
                        break;
                        /*Vector <uint64_t> load_dic;
                        for (int i=0;i<_dsts.size();i++){
                            dic.find_insert(_loads[i].cpu_load,i);
                            load_dic.push_back(_loads[i].cpu_load);
                        }
                        std::make_heap (load_dic.begin(), load_dic.end());
                        std::sort_heap(load_dic.begin(), load_dic.end());
                        return dic.find(load_dic.front()).value();*/
                    }
                    default:
                        assert(false);
                        break;
                }
                auto result = std::min_element(std::begin(_loads), std::end(_loads),comp);
                int sid = std::distance(std::begin(_loads), result);
                //click_chatter("%s\n--> %d",a.c_str(), sid);
                return sid;
            }
            case pow2: {
                //click_chatter("Power of 2 mode");
                int a = _selector.unchecked_at(click_random() % _selector.size());
                int b = _selector.unchecked_at(click_random() % _selector.size());
                switch(_lst_case) {
                    case connections: {
                        return (_loads[a].connection_load > _loads[b].connection_load?b:a);
                    }
                    case bytes: {
                        return (_loads[a].bytes_load > _loads[b].bytes_load?b:a);
                    }
                    case packets: {
                        return (_loads[a].packets_load > _loads[b].packets_load?b:a);
                    }
                    case cpu: {
                        int ret = (_loads[a].cpu_load > _loads[b].cpu_load?b:a);
                        //click_chatter("A %d B %d -> %d",a ,b, ret);
                        return ret;
                    }
                    default:
                        assert(false);
                }
                return -1; //unreachable
            }
            default: {
                //click_chatter("No mode set, go to bucket 0");
                return 0;
                break;
            }
        } //switch _lb_mode
    }
};

#endif
