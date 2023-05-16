import os
import json
import requests
import base64
import urllib
import logging

_logger = logging.getLogger(__name__)


def nextlinux_auth_init(username, password, auth_file, client_info_url,
                      token_url, conn_timeout, max_retries):
    if not username or not password or not auth_file or not client_info_url or not token_url or not conn_timeout or not max_retries:
        return (False)

    nextlinux_auth = {
        'username': '',
        'password': '',
        'max_retries': int(max_retries),
        'conn_timeout': int(conn_timeout),
        'client_info_url': client_info_url,
        'token_url': token_url,
        'auth_file': auth_file,
        'client_info': {},
        'token_info': {},
        'user_info': {},
    }

    if os.path.exists(auth_file):
        try:
            with open(auth_file, 'r') as FH:
                loaded_nextlinux_auth = json.loads(FH.read())
                nextlinux_auth.update(loaded_nextlinux_auth)
        except:
            pass

    if nextlinux_auth['username'] != username or nextlinux_auth[
            'password'] != password:
        nextlinux_auth['username'] = username
        nextlinux_auth['password'] = password
        nextlinux_auth_invalidate(nextlinux_auth)

    if not nextlinux_auth_save(nextlinux_auth, auth_file):
        _logger.error("could not save authentication details (" + auth_file +
                      ")")
        return (False)

    return (nextlinux_auth)


def get_current_user_info(nextlinux_auth):
    """
    Return the metadata about the current user as supplied by the nextlinux.io service. Includes permissions and tier access.

    :return: Dict of user metadata
    """

    user_url = nextlinux_auth['client_info_url'] + '/' + nextlinux_auth['username']
    user_timeout = 60
    retries = 3
    result = requests.get(
        user_url, headers={'x-nextlinux-password': nextlinux_auth['password']})
    if result.status_code == 200:
        user_data = json.loads(result.content)
    else:
        raise requests.HTTPError('Error response from service: {}'.format(
            result.status_code))
    return user_data


def nextlinux_auth_invalidate(nextlinux_auth):
    if 'client_info' in nextlinux_auth:
        nextlinux_auth['client_info'] = {}

    if 'token_info' in nextlinux_auth:
        nextlinux_auth['token_info'] = {}

    if 'user_info' in nextlinux_auth:
        nextlinux_auth['user_info'] = {}

    return (True)


def nextlinux_auth_save(nextlinux_auth, auth_file):
    if not nextlinux_auth or not auth_file:
        return (False)

    try:
        with os.fdopen(
                os.open(auth_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                        0600), 'w') as OFH:
            OFH.write(json.dumps(nextlinux_auth))
    except:
        return (False)

    return (True)


def nextlinux_auth_refresh(nextlinux_auth, forcerefresh=False):
    ret = {'success': False, 'text': "", 'status_code': 0}
    if not nextlinux_auth:
        ret['text'] = json.dumps("no nextlinux_auth token given as input")
        return (False, ret)

    new_nextlinux_auth = {}
    new_nextlinux_auth.update(nextlinux_auth)

    username = nextlinux_auth['username']
    password = nextlinux_auth['password']
    url_username = urllib.quote_plus(username)
    url_password = urllib.quote_plus(password)
    client_info_url = nextlinux_auth['client_info_url']
    token_url = nextlinux_auth['token_url']
    client_info = nextlinux_auth['client_info']
    token_info = nextlinux_auth['token_info']
    auth_file = nextlinux_auth['auth_file']
    user_info = nextlinux_auth['user_info']
    conn_timeout = int(nextlinux_auth['conn_timeout'])

    if not client_info:
        # get client info
        url = client_info_url + "/" + username
        headers = {'x-nextlinux-password': password}
        try:
            r = requests.get(url, headers=headers, timeout=conn_timeout)
        except:
            # print "request timed out"
            ret['text'] = json.dumps(
                "connection timed out: increase nextlinux_auth_conn_timeout higher or try again"
            )
            return (False, ret)

        ret['text'] = r.text
        ret['status_code'] = r.status_code

        if r.status_code == 200:
            new_nextlinux_auth['client_info'] = json.loads(r.text)['clients'][0]
            client_info = new_nextlinux_auth['client_info']
            ret['success'] = True
        elif r.status_code == 401:
            # print "bad username/password!"
            return (False, ret)
        else:
            # print "unknown login error: "
            return (False, ret)
    else:
        pass
        # print "skipping client_info get"

    b64bearertok = base64.b64encode(client_info['client_id'] + ":" +
                                    client_info['client_secret'])

    if not token_info:
        # get a token set
        payload = "grant_type=password&username=" + url_username + "&password=" + url_password
        headers = {
            'content-type': "application/x-www-form-urlencoded",
            'authorization': "Basic " + b64bearertok,
            'cache-control': "no-cache",
        }
        try:
            r = requests.post(token_url, headers=headers, data=payload)
        except:
            # print "request timed out"
            ret['text'] = json.dumps(
                "connection timed out: increase nextlinux_auth_conn_timeout higher or try again"
            )
            return (False, ret)

        ret['text'] = r.text
        ret['status_code'] = r.status_code
        if r.status_code == 200:
            new_nextlinux_auth['token_info'] = json.loads(r.text)
            ret['success'] = True
        else:
            # print "unknown token get error: "
            return (False, ret)

    elif forcerefresh:
        # print "refreshening"
        payload = "grant_type=refresh_token&refresh_token=" + token_info[
            'refreshToken']
        headers = {
            'content-type': "application/x-www-form-urlencoded",
            'authorization': "Basic " + b64bearertok,
            'cache-control': "no-cache",
        }
        try:
            r = requests.post(token_url, headers=headers, data=payload)
        except:
            # print "request timed out"
            ret['text'] = json.dumps(
                "connection timed out: increase nextlinux_auth_conn_timeout higher or try again"
            )
            return (False, ret)

        ret['text'] = r.text
        ret['status_code'] = r.status_code
        if r.status_code == 200:
            new_nextlinux_auth['token_info'] = json.loads(r.text)
            ret['success'] = True
        else:
            # print "refresh token invalid"
            return (False, ret)

    else:
        pass
        # print "skipping token_info get"

    if not user_info or forcerefresh:
        # Update the cached local user data
        new_user_info = get_current_user_info(nextlinux_auth)
        new_nextlinux_auth['user_info'] = new_user_info

    if nextlinux_auth != new_nextlinux_auth:
        nextlinux_auth.update(new_nextlinux_auth)
        nextlinux_auth_save(nextlinux_auth, auth_file)
    else:
        pass
        # print "skipping save"

    return (True, ret)


def nextlinux_auth_get(nextlinux_auth, url, timeout=None, retries=None):
    # make a request
    if not timeout:
        timeout = int(nextlinux_auth['conn_timeout'])

    if not retries:
        retries = int(nextlinux_auth['max_retries'])

    timeout = int(timeout)
    retries = int(retries)

    ret = {'status_code': 1, 'text': '', 'success': False}

    success = False
    count = 0
    # retries = nextlinux_auth['max_retries']

    while (not success and count < retries):
        count += 1
        _logger.debug("get attempt " + str(count) + " of " + str(retries))
        try:
            rc, record = nextlinux_auth_refresh(nextlinux_auth, forcerefresh=False)
            if not rc:
                # print "cannot get valid auth token"
                ret['text'] = record['text']
                return (ret)
            else:
                token_info = nextlinux_auth['token_info']
                accessToken = token_info['accessToken']
                headers = {
                    "Authorization": "Bearer " + accessToken,
                    "Cache-Control": "no-cache"
                }

                _logger.debug("making authenticated request to url: " +
                              str(url))
                r = requests.get(url, headers=headers, timeout=timeout)
                _logger.debug("\tresponse status_code: " + str(r.status_code))
                if r.status_code == 401:
                    _logger.debug("\tresponse body: " + str(r.text))
                    resp = json.loads(r.text)
                    if 'name' in resp and resp['name'] == 'invalid_token':
                        # print "bad tok - attempting to refresh"
                        rc, record = nextlinux_auth_refresh(nextlinux_auth,
                                                          forcerefresh=True)
                        if not rc:
                            # start over and retry
                            # print "refresh token failed, invalidating tok and starting over"
                            nextlinux_auth_invalidate(nextlinux_auth)
                    else:
                        success = True
                        ret['success'] = False
                        ret['err_msg'] = 'not authorized'

                elif r.status_code == 200:
                    success = True
                    ret['success'] = True
                elif r.status_code == 404:
                    success = True
                    ret['success'] = False
                elif r.status_code == 403:
                    success = True
                    ret['success'] = False
                    ret['err_msg'] = 'Access denied, check your access tier'

                ret['status_code'] = r.status_code
                ret['text'] = r.text

        except requests.exceptions.ConnectTimeout as err:
            _logger.debug("attempt failed: " + str(err))
            ret['text'] = "server error: timed_out: " + str(err)
            # return(ret)

        except Exception as err:
            _logger.debug("attempt failed: " + str(err))
            ret['text'] = "server error: " + str(err)

    return (ret)
