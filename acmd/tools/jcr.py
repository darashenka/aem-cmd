# coding: utf-8
from __future__ import unicode_literals

import sys
import os.path
import optparse
import json
import pprint
import traceback
from random import shuffle

import requests

from acmd import tool, log
from acmd import OK, SERVER_ERROR, USER_ERROR
from acmd.props import parse_properties
import acmd.config


parser = optparse.OptionParser("acmd <ls|find|dl|lsprop|setprop|rmprop> [options] <jcr path>")
parser.add_option("-r", "--raw",
                  action="store_const", const=True, dest="raw",
                  help="output raw response data")
parser.add_option("-f", "--fullpath",
                  action="store_const", const=True, dest="full_path",
                  help="output full paths instead of local")


@tool('diff')
class DiffTool(object):
    defaultIgnorePath = [ 'rep:policy' ]
    defaultIgnoreProps = [ 'cq:lastReplicatedBy','jcr:created', 'cq:lastReplicated', 'cq:lastReplicationAction','cq:lastModified','cq:lastModifiedBy','jcr:lastModified','jcr:createdBy', 'jcr:uuid', 'jcr:mixinTypes', 'jcr:versionHistory' ]

    server2 = ""
    path = ""
    options = None

    def setopt(self,argv):
        usage = "Usage: %prog diff [options] <server2> <jcr-path>"
        parser = optparse.OptionParser(usage=usage)
        parser.add_option("-r", "--raw",
                  action="store_const", const=True, dest="raw",
                  help="output raw response data")
        parser.add_option("-i", "--ignore-prop",
                  dest="ignoreProps", default=self.defaultIgnoreProps, action="append",
                  help="add properties to be ignored. default: %default")
        parser.add_option("-z", "--reset-prop",
                  dest="ignoreProps", const="", action="store_const",
                  help="Zero/reset properties to be ignored")
        parser.add_option("-I", "--ignore-path",
                  dest="ignorePath", default=self.defaultIgnorePath, action="append",
                  help="add path-elements should be ignored. default: %default")
        parser.add_option("-Z", "--reset-path",
                  dest="ignorePath", const="", action="store_const",
                  help="Zero/reset path-elements to be ignored")

        parser.add_option("-v", "--verbose",
                  action="store_const", const=True, dest="verbose",
                  help="show same properties")
        parser.add_option("-p", "--progress",
                  action="store_const", const=True, dest="progress",
                  help="show path to be done")
        parser.add_option("-R", "--random",
                  action="store_const", const=True, dest="random",
                  help="Randomize pathes")

        self.options, args = parser.parse_args(argv)

        if len(args) != 3:
            parser.print_help()
            sys.exit(3)
        server2 = args[1]
        self.path = args[2]

        rcfilename = acmd.get_rcfilename()
        config = acmd.read_config(rcfilename)
        self.server2 = config.get_server(server2)

    def execute(self, server, argv):
        log("Executing {}".format(self.name))
        self.setopt(argv)

        try:
            ret=self.diff_subnodes(server,self.server2,self.path)
        except KeyboardInterrupt:
            return 0


    def diff_subnodes(self,server1,server2,path):
##?? utf8 problem still not solved
#        if type(path) == str:
#            path = path.encode('utf-8')
        if self.options.progress:
            print ". {}".format(path)
        pp = pprint.PrettyPrinter(indent=4)
        subnodes = list()

        try:
          nodes1 = self.get_subnodes(server1, path)
          nodes2 = self.get_subnodes(server2, path)
        except Exception as e:
          pp.pprint(e)
          print(traceback.format_exc())
          return

        for path_segment, data in nodes1.items():
           if path_segment not in nodes1:
                   nodes1[path_segment] = None
           if path_segment not in nodes2:
                   nodes2[path_segment] = None
           if is_property(path_segment, nodes1[path_segment]) and is_property(path_segment,nodes2[path_segment]):
             if path_segment not in self.options.ignoreProps:
               if nodes1[path_segment] == nodes2[path_segment]:
                 if self.options.verbose:
                      print "+:{} [{}]: {}".format(path,path_segment, nodes1[path_segment]) # same properties
               else:
                      print "-:{} [{}]: {} <==> {}".format(path, path_segment, nodes1[path_segment],nodes2[path_segment])
           elif is_property(path_segment, nodes1[path_segment]) or is_property(path_segment,nodes2[path_segment]):
               print "!:{} [{}]: {} <==> {}".format(path, path_segment, nodes1[path_segment],nodes2[path_segment])
           else:
             if path_segment not in self.options.ignorePath:
               path2 = os.path.join(path,path_segment)
               if path2 not in subnodes:
                   subnodes.append(path2)
           del nodes1[path_segment]
           del nodes2[path_segment]
        if nodes2:
           print "%:{} ??? {}".format(path,nodes2) # nodes present on server2 but not in server1

        if self.options.random:
           shuffle(subnodes)
        for path_segment in subnodes:
           self.diff_subnodes(server1,server2,path_segment)

    def get_subnodes(self,server, path):
        url = server.url("{}.1.json".format(path))

        log("GETting service {}".format(url))
        resp = requests.get(url, auth=server.auth)
        if self.options.raw:
            print "{} {} {}".format(resp.url,resp.status_code,resp.encoding)
            print "{}".format(resp.text)
            if resp.status_code == 200:
               print "{}".format(resp.json())

        if resp.status_code != 200:
            raise Exception("error: Failed to get path {}{}, request returned {}\n".format(server,path, resp.status_code))

        return resp.json()


@tool('ls')
class ListTool(object):
    """ Since jcr operations are considered so common we extract what would otherwise be
        a jcr tool into separate smaller tools for ease of use.
    """

    def execute(self, server, argv):
        log("Executing {}".format(self.name))
        parser.set_usage("%prog ls [jcr-path]")
        options, args = parser.parse_args(argv)
        if len(args) >= 2:
            path = args[1]
            return list_node(server, options, path)
        else:
            ret = OK
            for path in sys.stdin:
                ret = ret | list_node(server, options, path.strip())
            return ret


def list_node(server, options, path):
    data = _get_subnodes(server, path)
    if options.raw:
        sys.stdout.write("{}\n".format(json.dumps(data, indent=4)))
    else:
        _list_nodes(path, data, full_path=options.full_path)
    return OK


def _list_nodes(path, nodes, full_path=False):
    for path_segment in nodes:
        if not is_property(path_segment, nodes[path_segment]):
            _list_node(path, path_segment, full_path)


def _list_node(path, path_segment, full_path=False):
    if full_path:
        full_path = os.path.join(path, path_segment)
        _list_path(full_path)
    else:
        _list_path(path_segment)


def _list_path(path):
    sys.stdout.write("{path}\n".format(path=path))


@tool('dl')
class DownloadTool(object):
    def execute(self, server, argv):
        parser.set_usage("%prog dl <jcr-path>")
        options, args = parser.parse_args(argv)
        if len(args) >= 2:
            path = args[1]
            return dl_node(server, options, path)
        else:
            ret = OK
            for line in sys.stdin:
                ret = ret | dl_node(server, options, line.strip())
            return ret

def dl_node(server, options, path):
    url = server.url("{path}".format(path=path))
    resp = requests.get(url, auth=server.auth)
    if resp.status_code != 200:
        sys.stderr.write("error: Failed to get path {}, request returned {}\n".format(path, resp.status_code))
        return SERVER_ERROR
    data = resp.text
    sys.stdout.write("{}\n".format(data))
    return OK

@tool('lsprop')
class InspectTool(object):
    def execute(self, server, argv):
        parser.set_usage("%prog lsprop <jcr-path>   # show properties")
        options, args = parser.parse_args(argv)
        if len(args) >= 2:
            path = args[1]
            return cat_node(server, options, path)
        else:
            ret = OK
            for line in sys.stdin:
                ret = ret | cat_node(server, options, line.strip())
            return ret


def cat_node(server, options, path):
    url = server.url("{path}.1.json".format(path=path))
    resp = requests.get(url, auth=server.auth)
    if resp.status_code != 200:
        sys.stderr.write("error: Failed to get path {}, request returned {}\n".format(path, resp.status_code))
        return SERVER_ERROR
    data = resp.json()
    if options.raw:
        sys.stdout.write("{}\n".format(json.dumps(data, indent=4)))
    else:
        for prop, data in data.items():
            print_property(prop, data)
    return OK

def print_property_value(data):
    if type(data) == str:
        data = data.encode('utf-8')
        sys.stdout.write(data)

    elif type(data) == unicode:
        sys.stdout.write(data)

    elif type(data) == list:
        sys.stdout.write('[ ')
        first=True
        for i in data:
            if not first:
                sys.stdout.write(', ')
            else:
                first=False
            print_property_value(i)
        sys.stdout.write(' ]')
    else:
        sys.stdout.write("{}".format(data))

def print_property(name,data):
    if not is_property(name, data):
        return

    if type(data) == str or type(data) == unicode:
        sys.stdout.write("{}:\t".format(name))
    else: 
        sys.stdout.write("{}[{}]:\t".format(name,type(data)))
    print_property_value(data)
    sys.stdout.write("\n")


@tool('find')
class FindTool(object):
    def execute(self, server, argv):
        parser.set_usage("%prog find [jcr-path]   # show all subnodes of the node")
        options, args = parser.parse_args(argv)

        try:
            if len(args) >= 2:
                path = args[1]
                return list_tree(server, options, path)
            else:
                ret = OK
                for line in sys.stdin:
                    ret = ret | list_tree(server, options, line.strip())
                return ret
        except KeyboardInterrupt:
            return USER_ERROR


def list_tree(server, options, path):
    _list_path(path)
    nodes = _get_subnodes(server, path)
    for path_segment, data in nodes.items():
        if not is_property(path_segment, data):
            list_tree(server, options, os.path.join(path, path_segment))
    return OK


def _get_subnodes(server, path):
    url = server.url("{path}.1.json".format(path=path))

    log("GETting service {}".format(url))
    resp = requests.get(url, auth=server.auth)

    if resp.status_code != 200:
        sys.stderr.write("error: Failed to get path {}, request returned {}\n".format(path, resp.status_code))
        sys.exit(-1)

    return resp.json()


def is_property(_, data):
    return not isinstance(data, dict)


@tool('cp')
class CpTool(object):

    def execute(self, server, argv):
        parser.set_usage("%prog cp <src-jcr-path> [src-jcr-path...] [dst-jcr-path]   # copy nodes")
        options, args = parser.parse_args(argv)
        if len(args) < 3:
            parser.print_help()
            sys.exit(3)
        args.pop(0)
        dst = args.pop()

        data = { ":operation": "copy", ":dest" : dst }
        if len(args) == 1:
           url = server.url(args.pop())
        else:
           url = server.url("/tmp/nonexistent")
           data[ ":applyTo" ] = list()
           for i in args:
              data[ ":applyTo" ].append(i)

        resp = requests.post(url, auth=server.auth,data=data)
        if resp.status_code != 200 and resp.status_code != 201:
            sys.stderr.write("error: Failed to copy, request returned {}\n".format(resp.status_code))
            return SERVER_ERROR
        if options.raw:
            sys.stdout.write("{}\n".format(resp.content))
        else:
            sys.stdout.write("{}\n".format(dst))
        return OK



@tool('mv')
class MvTool(object):

    def execute(self, server, argv):
        parser.set_usage("%prog mv <src-jcr-path> [src-jcr-path...] [dst-jcr-path]   # move nodes")
        options, args = parser.parse_args(argv)
        if len(args) < 3:
            parser.print_help()
            sys.exit(3)
        args.pop(0)
        dst = args.pop()

        data = { ":operation": "move", ":dest" : dst }
        if len(args) == 1:
           url = server.url(args.pop())
        else:
           url = server.url("/tmp/nonexistent")
           data[ ":applyTo" ] = list()
           for i in args:
             data[ ":applyTo" ].append(i)

        resp = requests.post(url, auth=server.auth,data=data)
        if resp.status_code != 200 and resp.status_code != 201:
            sys.stderr.write("error: Failed to move, request returned {}\n".format(resp.status_code))
            return SERVER_ERROR
        if options.raw:
            sys.stdout.write("{}\n".format(resp.content))
        else:
            sys.stdout.write("{}\n".format(dst))
        return OK



@tool('rm')
class RmTool(object):
    """ curl -X DELETE http://localhost:4505/path/to/node/jcr:content/nodeName -u admin:admin
    """

    def execute(self, server, argv):
        parser.set_usage("%prog rm [jcr-path]   # remove node")
        options, args = parser.parse_args(argv)
        if len(args) >= 2:
            path = args[1]
            return rm_node(server, options, path)
        else:
            for line in sys.stdin:
                path = line.strip()
                rm_node(server, options, path)
        return OK


def rm_node(server, options, path):
    url = server.url(path)
    resp = requests.delete(url, auth=server.auth)
    if resp.status_code != 204:
        sys.stderr.write("error: Failed to delete path {}, request returned {}\n".format(path, resp.status_code))
        return SERVER_ERROR
    if options.raw:
        sys.stdout.write("{}\n".format(resp.content))
    else:
        sys.stdout.write("{}\n".format(path))
    return OK


@tool('setprop')
class SetPropertyTool(object):
    """ curl -u admin:admin -X POST --data test=sample  http://localhost:4502/content/geometrixx/en/toolbar/jcr:content """

    def execute(self, server, argv):
        parser.set_usage("%prog setprop 'prop1=\"val1\",prop2=val3' <jcr-path>")
        options, args = parser.parse_args(argv)
        props = parse_properties(args[1])
        if len(args) >= 3:
            path = args[2]
            return set_node_properties(server, options, path, props)
        else:
            for line in sys.stdin:
                path = line.strip()
                set_node_properties(server, options, path, props)
            return OK


def set_node_properties(server, options, path, props):
    """ curl -u admin:admin -X POST --data test=sample  http://localhost:4502/content/geometrixx/en/toolbar/jcr:content """
    url = server.url(path)
    resp = requests.post(url, auth=server.auth, data=props)
    if resp.status_code != 200:
        sys.stderr.write("error: Failed to set property on path {}, request returned {}\n".format(path, resp.status_code))
        return SERVER_ERROR
    if options.raw:
        sys.stdout.write("{}\n".format(resp.content))
    else:
        sys.stdout.write("{}\n".format(path))
    return OK


@tool('rmprop')
class DeletePropertyTool(object):
    """ curl -u admin:admin -X POST --data test@Delete=  http://localhost:4502/content/geometrixx/en/toolbar/jcr:content """
    def execute(self, server, argv):
        options, args = parser.parse_args(argv)
        if len(args) <= 1:
            parser.print_help()
            return USER_ERROR
        prop_names = args[1].split(',')
        if len(args) >= 3:
            path = args[2]
            return rm_node_properties(server, options, prop_names, path)
        else:
            ret = OK
            for line in sys.stdin:
                path = line.strip()
                ret = ret | rm_node_properties(server, options, prop_names, path)
            return ret


def rm_node_properties(server, options, prop_names, path):
    props = {k + '@Delete': '' for k in prop_names}

    url = server.url(path)
    resp = requests.post(url, auth=server.auth, data=props)
    if resp.status_code != 200:
        sys.stderr.write("error: Failed to set property on path {}, request returned {}\n".format(path, resp.status_code))
        return SERVER_ERROR
    if options.raw:
        sys.stdout.write("{}\n".format(resp.content))
    else:
        sys.stdout.write("{}\n".format(path))
    return OK
