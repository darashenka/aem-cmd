# coding: utf-8
import sys
import optparse

import requests

from lxml import html

from acmd import tool
from acmd import USER_ERROR, SERVER_ERROR, OK, error
from acmd import parse_properties

parser = optparse.OptionParser("acmd users <create|setprop> [options] <username> [arguments]")
parser.add_option("-r", "--raw",
                  action="store_const", const=True, dest="raw",
                  help="output raw response data")
parser.add_option("-p", "--password",
                  dest="password", help="Set password of the user")


@tool('users')
class UserTool(object):
    def execute(self, server, argv):
        options, args = parser.parse_args(argv)
        action = get_action(args)
        actionarg = get_argument(args)
        if action == 'create':
            return create_user(server, options, actionarg)
        elif action == 'setprop':
            props = parse_properties(actionarg)
            username = get_argument(argv, 3)
            return set_profile_properties(server, options, username, props)
        else:
            parser.print_help()
            return USER_ERROR


def get_action(argv):
    if len(argv) < 2:
        return 'list'
    else:
        return argv[1]


def get_argument(argv, i=2):
    if len(argv) < i + 1:
        return None
    else:
        return argv[i]


def create_user(server, options, username):
    """ curl -u admin:admin -FcreateUser= -FauthorizableId=testuser -Frep:password=abc123
            http://localhost:4502/libs/granite/security/post/authorizables """
    assert len(username) > 0
    form_data = {
        'createUser': '',
        'authorizableId': username,
        'rep:password': options.password
    }
    url = server.url('/libs/granite/security/post/authorizables')
    resp = requests.post(url, auth=server.auth, data=form_data)
    if resp.status_code != 201:
        error("Failed to create user: {}".format(resp.content))
        return SERVER_ERROR
    if options.raw:
        sys.stdout.write("{}\n".format(resp.content))
    else:
        tree = html.fromstring(resp.text)
        path = tree.xpath('//div[@id="Path"]/text()')[0]
        sys.stdout.write("{}\n".format(path))
    return OK


def get_user_path(username):
    return "/home/users/{c}/{name}".format(c=username[0], name=username)


def set_profile_properties(server, options, username, props):
    """ curl -u admin:admin -Fprofile/age=29 http://localhost:4502/home/users/t/testuser1.rw.html """

    user_path = get_user_path(username)
    path = "{}.rw.html".format(user_path)
    url = server.url(path)
    props = {'profile/' + k: v for k, v in props.items()}
    resp = requests.post(url, auth=server.auth, data=props)
    if resp.status_code != 200:
        sys.stderr.write("error: Failed to set profile property on path {}, request returned {}\n".format(path, resp.status_code))
        return SERVER_ERROR
    if options.raw:
        sys.stdout.write("{}\n".format(resp.content))
    else:
        sys.stdout.write("{}\n".format(user_path))
    return OK
