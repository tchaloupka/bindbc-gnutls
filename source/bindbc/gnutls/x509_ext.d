module bindbc.gnutls.x509_ext;

import bindbc.gnutls.gnutls;
import bindbc.gnutls.x509;
import core.sys.posix.sys.select;

extern (C):

struct gnutls_subject_alt_names_st;
alias gnutls_subject_alt_names_t = gnutls_subject_alt_names_st*;

int gnutls_subject_alt_names_init (gnutls_subject_alt_names_t*);
void gnutls_subject_alt_names_deinit (gnutls_subject_alt_names_t sans);
int gnutls_subject_alt_names_get (gnutls_subject_alt_names_t sans, uint seq, uint* san_type, gnutls_datum_t* san, gnutls_datum_t* othername_oid);
int gnutls_subject_alt_names_set (gnutls_subject_alt_names_t sans, uint san_type, const(gnutls_datum_t)* san, const(char)* othername_oid);

int gnutls_x509_ext_import_subject_alt_names (const(gnutls_datum_t)* ext, gnutls_subject_alt_names_t, uint flags);
int gnutls_x509_ext_export_subject_alt_names (gnutls_subject_alt_names_t, gnutls_datum_t* ext);

alias gnutls_x509_ext_import_issuer_alt_name = gnutls_x509_ext_import_subject_alt_names;
alias gnutls_x509_ext_export_issuer_alt_name = gnutls_x509_ext_export_subject_alt_names;

struct gnutls_x509_crl_dist_points_st;
alias gnutls_x509_crl_dist_points_t = gnutls_x509_crl_dist_points_st*;

int gnutls_x509_crl_dist_points_init (gnutls_x509_crl_dist_points_t*);
void gnutls_x509_crl_dist_points_deinit (gnutls_x509_crl_dist_points_t);
int gnutls_x509_crl_dist_points_get (gnutls_x509_crl_dist_points_t, uint seq, uint* type, gnutls_datum_t* dist, uint* reason_flags);
int gnutls_x509_crl_dist_points_set (gnutls_x509_crl_dist_points_t, gnutls_x509_subject_alt_name_t type, const(gnutls_datum_t)* dist, uint reason_flags);

int gnutls_x509_ext_import_crl_dist_points (const(gnutls_datum_t)* ext, gnutls_x509_crl_dist_points_t dp, uint flags);
int gnutls_x509_ext_export_crl_dist_points (gnutls_x509_crl_dist_points_t dp, gnutls_datum_t* ext);

int gnutls_x509_ext_import_name_constraints (const(gnutls_datum_t)* ext, gnutls_x509_name_constraints_t nc, uint flags);
int gnutls_x509_ext_export_name_constraints (gnutls_x509_name_constraints_t nc, gnutls_datum_t* ext);

struct gnutls_x509_aia_st;
alias gnutls_x509_aia_t = gnutls_x509_aia_st*;

int gnutls_x509_aia_init (gnutls_x509_aia_t*);
void gnutls_x509_aia_deinit (gnutls_x509_aia_t);
int gnutls_x509_aia_get (gnutls_x509_aia_t aia, uint seq, gnutls_datum_t* oid, uint* san_type, gnutls_datum_t* san);
int gnutls_x509_aia_set (gnutls_x509_aia_t aia, const(char)* oid, uint san_type, const(gnutls_datum_t)* san);

int gnutls_x509_ext_import_aia (const(gnutls_datum_t)* ext, gnutls_x509_aia_t, uint flags);
int gnutls_x509_ext_export_aia (gnutls_x509_aia_t aia, gnutls_datum_t* ext);

int gnutls_x509_ext_import_subject_key_id (const(gnutls_datum_t)* ext, gnutls_datum_t* id);
int gnutls_x509_ext_export_subject_key_id (const(gnutls_datum_t)* id, gnutls_datum_t* ext);

struct gnutls_x509_aki_st;
alias gnutls_x509_aki_t = gnutls_x509_aki_st*;

int gnutls_x509_ext_export_authority_key_id (gnutls_x509_aki_t, gnutls_datum_t* ext);
int gnutls_x509_ext_import_authority_key_id (const(gnutls_datum_t)* ext, gnutls_x509_aki_t, uint flags);

int gnutls_x509_othername_to_virtual (const(char)* oid, const(gnutls_datum_t)* othername, uint* virt_type, gnutls_datum_t* virt);

int gnutls_x509_aki_init (gnutls_x509_aki_t*);
int gnutls_x509_aki_get_id (gnutls_x509_aki_t, gnutls_datum_t* id);
int gnutls_x509_aki_get_cert_issuer (gnutls_x509_aki_t aki, uint seq, uint* san_type, gnutls_datum_t* san, gnutls_datum_t* othername_oid, gnutls_datum_t* serial);
int gnutls_x509_aki_set_id (gnutls_x509_aki_t aki, const(gnutls_datum_t)* id);
int gnutls_x509_aki_set_cert_issuer (gnutls_x509_aki_t aki, uint san_type, const(gnutls_datum_t)* san, const(char)* othername_oid, const(gnutls_datum_t)* serial);
void gnutls_x509_aki_deinit (gnutls_x509_aki_t);

int gnutls_x509_ext_import_private_key_usage_period (const(gnutls_datum_t)* ext, time_t* activation, time_t* expiration);
int gnutls_x509_ext_export_private_key_usage_period (time_t activation, time_t expiration, gnutls_datum_t* ext);

int gnutls_x509_ext_import_basic_constraints (const(gnutls_datum_t)* ext, uint* ca, int* pathlen);
int gnutls_x509_ext_export_basic_constraints (uint ca, int pathlen, gnutls_datum_t* ext);

struct gnutls_x509_key_purposes_st;
alias gnutls_x509_key_purposes_t = gnutls_x509_key_purposes_st*;

int gnutls_x509_key_purpose_init (gnutls_x509_key_purposes_t* p);
void gnutls_x509_key_purpose_deinit (gnutls_x509_key_purposes_t p);
int gnutls_x509_key_purpose_set (gnutls_x509_key_purposes_t p, const(char)* oid);
int gnutls_x509_key_purpose_get (gnutls_x509_key_purposes_t p, uint idx, gnutls_datum_t* oid);

int gnutls_x509_ext_import_key_purposes (const(gnutls_datum_t)* ext, gnutls_x509_key_purposes_t, uint flags);
int gnutls_x509_ext_export_key_purposes (gnutls_x509_key_purposes_t, gnutls_datum_t* ext);

int gnutls_x509_ext_import_key_usage (const(gnutls_datum_t)* ext, uint* key_usage);
int gnutls_x509_ext_export_key_usage (uint key_usage, gnutls_datum_t* ext);

int gnutls_x509_ext_import_inhibit_anypolicy (const(gnutls_datum_t)* ext, uint* skipcerts);
int gnutls_x509_ext_export_inhibit_anypolicy (uint skipcerts, gnutls_datum_t* ext);

int gnutls_x509_ext_import_proxy (const(gnutls_datum_t)* ext, int* pathlen, char** policyLanguage, char** policy, size_t* sizeof_policy);
int gnutls_x509_ext_export_proxy (int pathLenConstraint, const(char)* policyLanguage, const(char)* policy, size_t sizeof_policy, gnutls_datum_t* ext);

struct gnutls_x509_policies_st;
alias gnutls_x509_policies_t = gnutls_x509_policies_st*;

int gnutls_x509_policies_init (gnutls_x509_policies_t*);
void gnutls_x509_policies_deinit (gnutls_x509_policies_t);

int gnutls_x509_policies_get (gnutls_x509_policies_t policies, uint seq, gnutls_x509_policy_st* policy);
int gnutls_x509_policies_set (gnutls_x509_policies_t policies, const(gnutls_x509_policy_st)* policy);

int gnutls_x509_ext_import_policies (const(gnutls_datum_t)* ext, gnutls_x509_policies_t policies, uint flags);
int gnutls_x509_ext_export_policies (gnutls_x509_policies_t policies, gnutls_datum_t* ext);

int gnutls_x509_ext_import_tlsfeatures (const(gnutls_datum_t)* ext, gnutls_x509_tlsfeatures_t, uint flags);

int gnutls_x509_ext_export_tlsfeatures (gnutls_x509_tlsfeatures_t f, gnutls_datum_t* ext);

int gnutls_x509_tlsfeatures_add (gnutls_x509_tlsfeatures_t f, uint feature);
