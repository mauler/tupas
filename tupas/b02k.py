from urllib.parse import urlparse, parse_qs, urlencode
from typing import NamedTuple, Dict, List

import hashlib


B02K_MAC = 'B02K_MAC'

B02K_KEYS = (
    'B02K_VERS',
    'B02K_TIMESTMP',
    'B02K_IDNBR',
    'B02K_STAMP',
    'B02K_CUSTNAME',
    'B02K_KEYVERS',
    'B02K_ALG',
    'B02K_CUSTID',
    'B02K_CUSTTYPE',
)


class B02KInfo(NamedTuple):
    B02K_VERS: str
    B02K_TIMESTMP: str
    B02K_IDNBR: str
    B02K_STAMP: str
    B02K_CUSTNAME: str
    B02K_KEYVERS: str
    B02K_ALG: str
    B02K_CUSTID: str
    B02K_CUSTTYPE: str


def declare_info(info: Dict) -> B02KInfo:
    """
    Declares a new :class:`B02KInfo` from a :class:`dict` ignoring keys that
    are not attributes.

    :param info: Dictionary to be used.
    :return: New :class:`B02kInfo` using the attributes available on the
        dictionary.
    """
    params = {k: v for k, v in info.items() if k in B02K_KEYS}
    return B02KInfo(**params)


def calculate_signature(b02kinfo: B02KInfo, secret: str) -> str:
    """
    Calculates the and sign the b02kinfo using a secret.

    This function concats all B02K with information with "&" between them and
    append the secret input.

    :param b02kinfo: B02K information.
    :param secret: Salt to be used on the sign.
    :return: The signature.
    """
    raw = (f'{b02kinfo.B02K_VERS}&'
           f'{b02kinfo.B02K_TIMESTMP}&'
           f'{b02kinfo.B02K_IDNBR}&'
           f'{b02kinfo.B02K_STAMP}&'
           f'{b02kinfo.B02K_CUSTNAME}&'
           f'{b02kinfo.B02K_KEYVERS}&'
           f'{b02kinfo.B02K_ALG}&'
           f'{b02kinfo.B02K_CUSTID}&'
           f'{b02kinfo.B02K_CUSTTYPE}&'
           f'{secret}&')
    return hashlib.sha256(raw.encode()).hexdigest().upper()


def get_qs_dict(query: str) -> Dict[str, str]:
    """
    Converts a query string into a dictionary, raises :class:`ValueError`
    if double keys are specified.

    :param query: Querystring as string
    :return: Querystring values dictionary.
    """
    qs = {}
    for k, v in parse_qs(query).items():
        if len(v) != 1:
            raise ValueError(v)

        qs[k] = v[0]
    return qs


def format_names(fullname: str) -> List[str]:
    """
    Formats first and last name, capitalizing them.

    :param fullname: Fullname to be capitalized.
    :return: List with 2 index, first name and last name capitalized.
    """
    return fullname.title().split(' ', 1)


def build_success_url(b02kinfo: B02KInfo, secret: str) -> str:
    """
    Builds a url in case of succesful validated url.

    :param b02kinfo: B02K information.
    :param secret: Salt to be used on success signature.
    :return: Sucess url with signature.
    """
    first, last = format_names(b02kinfo.B02K_CUSTNAME)
    signature = build_success_hash(first, last, secret)

    querystring = urlencode({
        'firstname': first,
        'lastname': last,
        'hash': signature})

    return f'?{querystring}'


def build_success_hash(first: str, last: str, secret: str) -> str:
    """
    Creates success hash from first name and last name using a salt.

    :param first: First name capitalized
    :param last: Last name capitalized
    :param secret: Salt
    :return: Signed hash
    """
    raw = f'firstname={first}&lastname={last}#{secret}'
    return hashlib.sha256(raw.encode()).hexdigest()


def get_redirect_url(url: str, inputsecret: str, outputsecret: str,
                     error_url: str) -> str:
    """
    Tries to validate the signature URL, if it is valid the redirect url
    is returned, else the error url.

    :param url: URL Format according Tupas
    :param inputsecret: Salt used to solve signature
    :param outputsecret: Salt to be used on success redirect url
    :param error_url: Url to be used in case of error
    :return: Validity of URL
    """
    parsed = urlparse(url)
    qs = get_qs_dict(parsed.query)
    b02kinfo = declare_info(qs)
    signature = calculate_signature(b02kinfo, inputsecret)

    if signature == qs[B02K_MAC]:
        success_url = build_success_url(b02kinfo, outputsecret)
        return success_url
    else:
        return error_url
