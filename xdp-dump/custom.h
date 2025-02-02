#ifndef CUSTOM_H
#define CUSTOM_H

#define BULK_BOUND 4
#define NUM_FEATURES 81
#define CLUMP_TIMEOUT 1

int total_flow = 0;
int size = 0;
int size_input = 0;

struct flow_tuple {
	uint32_t src_ip;
	uint32_t dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t protocol;
};

struct will_be_used {
	int payload_size;
	struct in_addr src_ip;
	struct in_addr dst_ip;
	uint16_t src_port;
	uint16_t dst_port;
	uint8_t protocol;
	bool direction; //1 -> Forward, 0 -> Backward
	u_int flag;
    u_int size_ip;
    u_int size_tcp;
	double timestamp;
};

#define TABLE_SIZE_A 300000
struct will_be_used buff__table[TABLE_SIZE_A];

// Data structure to store flow timing information
struct flow_info {
	double start_time;
	double end_time;
	double ssquare_payload;
	double fwd_data_pkts_tot;
	double bwd_data_pkts_tot;
	double fwd_ssquare_payload;
	double bwd_ssquare_payload;

	// duplicate features (by cicflowmeter)
	double fwd_pkt_len_mean;
	double bwd_pkt_len_mean;
	double fwd_urg_flags;
	int fwd_pkts_tot;
	int bwd_pkts_tot;
	double totlen_fwd_pkts;
	double totlen_bwd_pkts;
	// end

	double backward_bulk_last_timestamp;
	double forward_bulk_start_tmp;
	double forward_bulk_last_timestamp;
	double forward_bulk_size_tmp;
	double forward_bulk_count_tmp;
	double forward_bulk_packet_count;
	double forward_bulk_count;
	double forward_bulk_size;
	double forward_bulk_duration;
	double backward_bulk_count;
	double backward_bulk_count_tmp;
	double backward_bulk_start_tmp;
	double backward_bulk_size_tmp;
	double backward_bulk_packet_count;
	double backward_bulk_size;
	double backward_bulk_duration;

	// end
	double fwd_ssquare_iat;
	double bwd_ssquare_iat;
	double ssquare_iat;
	float fwd_pkts_per_sec;
	float bwd_pkts_per_sec;
	int fwd_header_size_tot;
	int fwd_header_size_min;
	int fwd_header_size_max;
	int bwd_header_size_tot;
	int bwd_header_size_min;
	int bwd_header_size_max;
	int flow_FIN_flag_count;
	int flow_SYN_flag_count;
	int flow_RST_flag_count;
	int fwd_PSH_flag_count;
	int bwd_PSH_flag_count;
	int flow_ACK_flag_count;
	int fwd_URG_flag_count;
	int bwd_URG_flag_count;
	int flow_CWR_flag_count;
	int flow_ECE_flag_count;
	int fwd_pkts_payload_min;
	int fwd_pkts_payload_max;
	int fwd_pkts_payload_count;
	int fwd_pkts_payload_tot;
	double fwd_pkts_payload_avg;
	double fwd_pkts_payload_std;
	int bwd_pkts_payload_min;
	int bwd_pkts_payload_max;
	int bwd_pkts_payload_count;
	int bwd_pkts_payload_tot;
	double bwd_pkts_payload_avg;
	double bwd_pkts_payload_std;
	int flow_pkts_payload_min;
	int flow_pkts_payload_max;
	int flow_pkts_payload_tot;
	int flow_pkts_payload_count;
	double flow_pkts_payload_avg;
	double flow_pkts_payload_std;
	double fwd_iat_min;
	double fwd_iat_max;
	double fwd_iat_tot;
	double fwd_iat_avg;
	int fwd_iat_count;
	double fwd_iat_std;
	double bwd_iat_min;
	double bwd_iat_max;
	double bwd_iat_tot;
	double bwd_iat_avg;
	int bwd_iat_count;
	double bwd_iat_std;
	double flow_iat_min;
	double flow_iat_max;
	double flow_iat_tot;
	double flow_iat_avg;
	int flow_iat_count;
	double flow_iat_std;
	int total_payload;
	double active_min;
	double active_max;
	double active_tot;
	double active_std;
	double active_duration;
	double active_avg;
};

#define HASH_TABLE_SIZE 900000

struct flow_info *flow_table[HASH_TABLE_SIZE];

float input_data[900000][NUM_FEATURES + 3];
float total_packets_byte = 0;

//this function used to create hash flow
unsigned int hash_flow(struct flow_tuple *key)
{
	return (key->src_ip ^ key->dst_ip ^ key->src_port ^ key->dst_port ^
		key->protocol) %
	       HASH_TABLE_SIZE;
}

//this function used to convert from network byte order to host byte order
float network_byte_order_to_float(uint32_t value)
{
	
	uint32_t temp = ntohl(value);
	float result;
	memcpy(&result, &temp, sizeof(result)); // Copy bits back into float
	return result;
}


void addStructElement(struct will_be_used new_element)
{
	// #pragma omp critical
	if (size < TABLE_SIZE_A) {
		buff__table[size] = new_element; // Add the new element at the end
		size++; // Increase the size count
	} else {
		printf("Table is full, cannot add more elements.\n");
	}
}



#endif