#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gnutls/x509.h>
#include <gnutls/x509-ext.h>
#include <assert.h>
#include "pkix.asn.h"

/* Encodes the provided data as a PKIX Extension structure.
 */
static void create_ext(const char *oid, const gnutls_datum_t *data, gnutls_datum_t *out)
{
	int ret, len;
	node_asn *definitions = NULL;
	node_asn *ext = NULL;

	assert(asn1_array2tree (pkix_asn1_tab, &definitions, NULL) == ASN1_SUCCESS);
	assert(asn1_create_element (definitions, "PKIX1.Extension", &ext) == ASN1_SUCCESS);

	assert(asn1_write_value(ext, "extnID", oid, 1) == ASN1_SUCCESS);
	assert(asn1_write_value(ext, "critical", "FALSE", 1) == ASN1_SUCCESS);
	assert(asn1_write_value(ext, "extnValue", data->data, data->size) == ASN1_SUCCESS);

	len = 0;
	assert(asn1_der_coding (ext, "", NULL, &len, NULL) == ASN1_MEM_ERROR);

	out->data = malloc(len);
	assert(out->data != NULL);

	assert(asn1_der_coding (ext, "", out->data, &len, NULL) == ASN1_SUCCESS);

	out->size = len;

	asn1_delete_structure (&ext);
	asn1_delete_structure (&definitions);
	return;
}

void funny_print(const gnutls_datum_t *data)
{
	unsigned i;

	for (i=0;i<data->size;i++) {
		printf("%%%.2x", (unsigned)data->data[i]);
	}
	printf("\n");
}

int main(int argc, char **argv)
{
	gnutls_x509_name_constraints_t nc;
	gnutls_datum_t der, out;
	unsigned i;

	if (argc < 2) {
		printf("usage: %s [domain1] [domain2] ...\n", argv[0]);
		return 1;
	}

	assert(gnutls_x509_name_constraints_init(&nc) >= 0);
	for (i=0;i<argc-1;i++) {
		gnutls_datum_t name;
		name.data = argv[i+1];
		name.size = strlen(argv[i+1]);
		assert(gnutls_x509_name_constraints_add_permitted(nc,
							   GNUTLS_SAN_DNSNAME,
							   &name) >= 0);
	}

	assert(gnutls_x509_ext_export_name_constraints(nc, &der) >= 0);
	gnutls_x509_name_constraints_deinit(nc);

	create_ext(GNUTLS_X509EXT_OID_NAME_CONSTRAINTS, &der, &out);
	gnutls_free(der.data);

	funny_print(&out);
	free(out.data);
}
