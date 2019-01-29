import unittest

from tupas import b02k


class BaseTest(unittest.TestCase):
    B02KDICT = {
        'B02K_VERS': '0003',
        'B02K_TIMESTMP': '50020181017141433899056',
        'B02K_IDNBR': '2512408990',
        'B02K_STAMP': '20010125140015123456',
        'B02K_CUSTNAME': 'FIRST LAST',
        'B02K_KEYVERS': '0001',
        'B02K_ALG': '03',
        'B02K_CUSTID': '9984',
        'B02K_CUSTTYPE': '02'}

    B02KINFO = b02k.B02KInfo(
        B02K_VERS='0003',
        B02K_TIMESTMP='50020181017141433899056',
        B02K_IDNBR='2512408990',
        B02K_STAMP='20010125140015123456',
        B02K_CUSTNAME='FIRST LAST',
        B02K_KEYVERS='0001',
        B02K_ALG='03',
        B02K_CUSTID='9984',
        B02K_CUSTTYPE='02')

    INPUT_SECRET = 'inputsecret'

    SIGNATURE = ('EBA959A76B87AE8996849E7C0C08D4AC44B053183BE12C0DAC2AD0C86F9'
                 'F2542')

    SUCCESS_REDIRECT_HASH = ('4f6536ca2a23592d9037a4707bb44980b9bd2d4250fc1c'
                             '833812068ccb000712')


class B02KTest(BaseTest):

    def test_declare_info(self):
        """ Dictionary with keys that are not used on :class:`tupas.b02k.B02KInfo`
        should be ignored."""
        params = self.B02KDICT.copy()
        params.update({'Invalid-Key': 'Invalid-Value'})
        self.assertEqual(b02k.declare_info(params), self.B02KINFO)

    def test_calculate_signature(self):
        self.assertEqual(b02k.calculate_signature(self.B02KINFO,
                                                  self.INPUT_SECRET),
                         self.SIGNATURE)

    def test_get_qs_dict(self):
        self.assertEqual(b02k.get_qs_dict('name=paulo'), {'name': 'paulo'})

        with self.assertRaises(ValueError):
            b02k.get_qs_dict('name=paulo&name=chaves')

    def test_format_names(self):
        self.assertEquals(b02k.format_names('paulo chaves'),
                          ['Paulo', 'Chaves'])

        # Tests failsafe in case of wrong formated fullname (more than 2 names)
        self.assertEquals(b02k.format_names('paulo r m chaves'),
                          ['Paulo', 'R M Chaves'])


class URLTest(BaseTest):

    VALID_URL = (
        'http://someserver.com/?'
        'B02K_VERS=0003&'
        'B02K_TIMESTMP=50020181017141433899056&'
        'B02K_IDNBR=2512408990&'
        'B02K_STAMP=20010125140015123456&'
        'B02K_CUSTNAME=FIRST%20LAST&'
        'B02K_KEYVERS=0001&'
        'B02K_ALG=03&'
        'B02K_CUSTID=9984&'
        'B02K_CUSTTYPE=02&'
        'B02K_MAC=EBA959A76B87AE8996849E7C0C08D4AC44B053183BE12C0DAC2AD0C86F9'
        'F2542'
    )

    OUTPUT_SECRET = 'outputsecret'

    SUCCESS_URL = (
        '?firstname=First&lastname=Last&''hash='
        '4f6536ca2a23592d9037a4707bb44980b9bd2d4250fc1c833812068ccb000712')

    ERROR_URL = '/error/'

    INVALID_URL = (
        'http://someserver.com/?'
        'B02K_VERS=0003&'
        'B02K_TIMESTMP=50020181017141433899056&'
        'B02K_IDNBR=2512408990&'
        'B02K_STAMP=20010125140015123456&'
        'B02K_CUSTNAME=FIRST%20LAST&'
        'B02K_KEYVERS=0001&'
        'B02K_ALG=03&'
        'B02K_CUSTID=9984&'
        'B02K_CUSTTYPE=02&'
        'B02K_MAC=INVALID_SIGNATURE'
    )

    def test_build_success_url(self):
        self.assertEqual(b02k.build_success_url(self.B02KINFO,
                                                self.OUTPUT_SECRET),
                         self.SUCCESS_URL)

    def test_build_success_hash(self):
        self.assertEqual(b02k.build_success_hash('First',
                                                 'Last',
                                                 self.OUTPUT_SECRET),
                         self.SUCCESS_REDIRECT_HASH)

    def test_valid_redirect_url(self):
        self.assertEqual(b02k.get_redirect_url(self.VALID_URL,
                                               self.INPUT_SECRET,
                                               self.OUTPUT_SECRET,
                                               self.ERROR_URL),
                         self.SUCCESS_URL)

    def test_invalid_redirect_url(self):
        self.assertEqual(b02k.get_redirect_url(self.INVALID_URL,
                                               self.INPUT_SECRET,
                                               self.OUTPUT_SECRET,
                                               self.ERROR_URL),
                         self.ERROR_URL)


class NONASCIITest(unittest.TestCase):

    NON_ASCII_CUSTNAME = 'V%C4IN%D6%20M%C4KI'

    NON_ASCII_CUSTNAME_DECODED = 'V�IN� M�KI'

    NON_ASCII_QUERYSTRING = (
        'B02K_CUSTNAME=V%C4IN%D6%20M%C4KI'
    )

    OUTPUT_SECRET = 'output'

    def test_non_ascii_get_qs_dict(self):
        self.assertEqual(b02k.get_qs_dict(self.NON_ASCII_QUERYSTRING),
                         {'B02K_CUSTNAME': self.NON_ASCII_CUSTNAME_DECODED})

    def test_non_ascii_signature(self):
        first, last = b02k.format_names(self.NON_ASCII_CUSTNAME_DECODED)
        decoded_signature = b02k.build_success_hash(first, last,
                                                    self.OUTPUT_SECRET)

        # Hash generated from decoded customer name should be the same as
        # the hash generated via url encoded customer name
        first, last = \
            b02k.format_names(
                b02k.get_qs_dict(self.NON_ASCII_QUERYSTRING)['B02K_CUSTNAME'])

        encoded_signature = b02k.build_success_hash(first, last,
                                                    self.OUTPUT_SECRET)

        self.assertEqual(decoded_signature, encoded_signature)
