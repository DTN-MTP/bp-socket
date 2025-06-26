#ifndef EID_H
#define EID_H

enum bp_eid_scheme {
	UNKNOWN_SCHEME = -1,
	IPN,
};

enum bp_eid_scheme parse_eid_scheme(char* cursor, int eid_size);
int str_find_char_bounded(char* cursor, char target, int* remaining);
int str_find_term_bounded(char* cursor, int* remaining);
int str_read_uint_bounded(const char* str, size_t len);
int ipn_eid_parse(char* cursor, int remaining);
int get_service_id(const char* eid_str);

#endif
