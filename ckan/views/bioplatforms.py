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


# Registration requests for these projects will automatically
# grant organization membership without human review.
AUTOREGISTER_PROJECTS = {
    'Australian Microbiome': 'australian-microbiome',
    'Great Barrier Reef': 'bpa-great-barrier-reef',
    'Wheat Pathogen Transcript': 'bpa-wheat-pathogens-transcript',
    'Wheat Pathogens Genomes': 'bpa-wheat-pathogens-genomes',
    'Wheat Cultivars': 'bpa-wheat-cultivars'
}


def email_new_user_request_to_helpdesk(request_data):
    '''
    Send an email containing the user request details to Zendesk.
    '''
    # bpa user registration
    details = {
        "username": request_data[u'name'],
        "name": request_data[u'fullname'],
        "email": request_data[u'email'],
        "reason_for_request": request_data[u'request_reason'],
        "project_of_interest": request_data[u'project_of_interest']
    }

    email_body = "There is a new user registration request. \
        \nThe user's details are as follows: \
        \n\
        \nUsername: {username}\
        \nName: {name} \
        \nEmail: {email} \
        \nReason for Request: {reason_for_request} \
        \nProject of Interest: {project_of_interest} ".format(**details)

    mailer.mail_recipient(
        'Bioplatforms Helpdesk',
        os.environ.get('BIOPLATFORMS_HELPDESK_ADDRESS'),
        'Bioplatforms New User Registration Request',
        email_body)


def log_new_user_request_in_bpam(request_data):
    '''
    Send the user registration details to bpam for recording/tracking in the database.
    '''
    # bpa user registration
    bpam_log_url = os.environ.get('BPAM_REGISTRATION_LOG_URL')
    bpam_log_key = os.environ.get('BPAM_REGISTRATION_LOG_KEY')

    if not bpam_log_url or not bpam_log_key:
        log.warning(
            'Error sending user details to BPAM server. BPAM URL or Key is not set.')
        return

    details = {
        "username": request_data[u'name'],
        "name": request_data[u'fullname'],
        "email": request_data[u'email'],
        "reason_for_request": request_data[u'request_reason'],
        "project_of_interest": request_data[u'project_of_interest'],
        "key": bpam_log_key,
    }

    r = requests.post(bpam_log_url, data=details)

    if r.status_code == 200:
        log.warning('User details sent to BPAM server successfully.')
    else:
        log.warning('Error sending user details to BPAM server.')


def bioplatforms_register_user(data_dict):
    # storing user details for bpa user registration workflow
    # After user's been created in ckan, grant membership for requested organization(bpa project)
    project_of_interest = data_dict[u'project_of_interest']
    if project_of_interest in AUTOREGISTER_PROJECTS:
        username = data_dict[u'name']
        ckan_api_url = os.environ.get('LOCAL_CKAN_API_URL')
        ckan_api_key = os.environ.get('CKAN_API_KEY')

        data = {
            'id': AUTOREGISTER_PROJECTS[project_of_interest],
            'username': username,
            'role': 'member'
        }

        ckan = ckanapi.RemoteCKAN(ckan_api_url, ckan_api_key)
        ckan.call_action(
            'organization_member_create',
            data_dict=data
        )


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
