# encoding: utf-8
import logging

import ckanapi
import requests
import time

import os
import json
import hmac

import ckan.lib.mailer as mailer
import ckan.lib.base as base
import ckan.lib.helpers as h
import ckan.logic as logic

from ckan.common import g


log = logging.getLogger(__name__)


def bioplatforms_webtoken():
    # bpa-otu auth
    if not g.user:
        base.abort(403, 'Please log into CKAN.')

    user_details = {
        'user': g.user,
        'auth_user_obj': g.userobj
    }

    user_id = {'id': g.userobj.id}
    user_data = logic.get_action('user_show')(user_details, user_id)

    organisations = []

    user_organisations = h.organizations_available(permission='read')
    for uo in user_organisations:
        organisations.append(uo['name'])

    data_portion = {
        'email': user_data['email'],
        'timestamp': time.time(),
        'organisations': organisations
    }

    data_portion = json.dumps(data_portion)

    secret_key = os.environ.get('BPAOTU_AUTH_SECRET_KEY')
    digest_maker = hmac.new(secret_key)
    digest_maker.update(data_portion)
    digest = digest_maker.hexdigest()

    return (digest + "||" + data_portion)
