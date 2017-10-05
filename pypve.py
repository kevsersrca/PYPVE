import json
import requests
import sys


class pypve:

    node = 'proxmox'

    """
    Constrctur method
    @param path
    @param client
    @param key
    """
    def __init__(self, path, client, key):
        """ Fields"""
        self.path = path
        self.full_path = "https://%s:8006/api2/json/access/ticket" % (self.path)
        self.client = client
        self.key = key
        self.ticket = ""
        self.CSRFToken = ""

        """ 
        Authentification request and return message
        """
        try:
            self.message = requests.post(self.full_path, verify=False, data={"username": self.client, "password": self.key})
        except:
            raise ValueError('hata')
        """ 
        Authentification message control
        """
        if not self.message.ok:
            raise AssertionError('Authentification Failed : \n {}'.format(self.message))

        self.data = {
            'status': {'code': self.message.status_code, 'ok': self.message.ok, 'reason': self.message.reason}}
        self.data.update(self.message.json())

        self.ticket = {'PVEAuthCookie': self.data['data']['ticket']}
        self.CSRF = self.data['data']['CSRFPreventionToken']


    def connect(self, method, option, post_data):
        """
        Connect the api
        """
        self.full_url = "https://%s:8006/api2/json/%s" % (self.path, option)

        httpheaders = {'Accept': 'application/json', 'Content-Type': 'application/x-www-form-urlencoded'}
        requests.packages.urllib3.disable_warnings()

        if method == "post":
            httpheaders['CSRFPreventionToken'] = str(self.CSRF)
            self.response = requests.post(self.full_url, verify=False, data=post_data, cookies=self.ticket, headers=httpheaders)

        elif method == "put":
            httpheaders['CSRFPreventionToken'] = str(self.CSRF)
            self.response = requests.put(self.full_url, verify=False, data=post_data, cookies=self.ticket, headers=httpheaders)
        elif method == "delete":
            httpheaders['CSRFPreventionToken'] = str(self.CSRF)
            self.response = requests.delete(self.full_url, verify=False, data=post_data, cookies=self.ticket, headers=httpheaders)
        elif method == "get":
            self.response = requests.get(self.full_url, verify=False, cookies=self.ticket)

        try:
            self.json = self.response.json()
            self.json.update({'status': {'code': self.response.status_code, 'ok': self.response.ok, 'reason': self.response.reason}})
            return self.json
        except:
            print("Error in trying to process JSON")
            print(self.response)
            if self.response.status_code == 401 and (
                    not sys._getframe(1).f_code.co_name == sys._getframe(0).f_code.co_name):
                print "Unexpected error: %s : %s" % (str(sys.exc_info()[0]), str(sys.exc_info()[1]))
                print "try to recover connection auth"

    def getKvmIndex(self,):
        """Get kvm index information. Returns JSON"""
        data = self.connect('get', 'nodes/%s/qemu'%(self.node), None)
        return data

    def postCreateKvm(self, post_data={}):
        """
        Create or restore kvm

        Optional rules : post_data {
        'autostart' : boolen
        'cdrom' : volume
        'ostype' : string | other / wxp / w2k / w2k3 / w2k8 / vista / win7 / win8 / l24 / l26 / solaris ]
        'memory' : integer | MB
        'scsi0' : string | local-lvm:<disksize>
        ...
        }
        """
        post_data = post_data
        data = self.connect('post', 'nodes/%s/qemu' %(self.node), post_data)
        return data

    def getKVmDirectoryIndex(self, vmid):
        """ Get KVm Directory Index"""
        data = self.connect('get', 'nodes/%s/qemu/%s' %(self.node, vmid), None)
        return data

    def deleteKvm(self, vmid):
        """ Delete Kvm"""
        data = self.connect('delete', 'nodes/%s/qemu/%s' %(self.node, vmid), None)
        return data


    """ Firewall Operations """

    def getKvmFirewallDirectoryIndex(self, vmid):
        """ Firewall Directory Index"""
        data = self.connect('get', 'nodes/%s/qemu/%s/firewall' %(self.node, vmid), None)
        return data

    def getKvmFirewallListAllias(self, vmid):
        """ Firewall Allias List """
        data = self.connect('get', 'nodes/%s/qemu/%s/firewall/aliases' %(self.node, vmid), None)
        return data

    def createKvmFirewallAllias(self, vmid, post_data={}):
        """
        Create IP or Network Alias
        Requeired rules : post_data {
        'cidr' : string | Network/IP spectification in CIDR Format
        'name' : string | Allias Name
        }
        """
        data = self.connect('post', 'nodes/%s/qemu/%s/firewall/aliases' %(self.node, vmid), post_data)
        return data

    def kvmFirewallReadAllias(self, vmid, name):
        """Read alias. Return Object"""
        data = self.connect('get', 'nodes/%s/qemu/%s/firewall/aliases/%s' %(self.node, vmid, name), None)
        return data

    def editFirewallAllias(self, vmid, name, post_data={}):
        """
        Requeired rules : post_data {
        'cidr' : string | Network/IP spectification in CIDR Format
        'name' : string | Allias Name
        }
        :param vmid:
        :param name:
        :param post_data:
        :return data:
        """
        data = self.connect('put', 'nodes/%s/qemu/%s/firewall/aliases/%s' %(self.node, vmid, name), post_data)
        return data

    def removeFirewallAllias(self, vmid, name):
        """
        :param vmid:
        :param name:
        :return data:
        """
        data = self.connect('delete', 'nodes/%s/qemu/%s/firewall/aliases/%s' % (self.node, vmid, name), None)
        return data

    def listFirewallIpset(self, vmid):
        """
        :param vmid:
        :return data:
        """
        data = self.connect('get', 'nodes/%s/qemu/%s/firewall/ipset' % (self.node, vmid), None)
        return data

    def createFirewallIpset(self, vmid, post_data={}):
        """
        post_data = {
        'name' = string
        'digest' = string
        }
        :param vmid:
        :param post_data:
        :return data:
        """
        data = self.connect('post', 'nodes/%s/qemu/%s/firewall/ipset' % (self.node, vmid), post_data)
        return data

    def listFirewallIpsetContent(self, vmid, name):
        """
        :param vmid:
        :param name:
        :return data:
        """
        data = self.connect('get', 'nodes/%s/qemu/%s/firewall/ipset/%s' % (self.node, vmid, name), None)
        return data

    def addFirewallIpsetContent(self, vmid, name, post_data=None):
        """
        :param vmid:
        :param name:
        :return data:
        """
        data = self.connect('post', 'nodes/%s/qemu/%s/firewall/ipset/%s' % (self.node, vmid, name), post_data)
        return data

    def deleteFirewallIpsetContent(self, vmid, name):
        """
        :param vmid:
        :param name:
        :return data:
        """
        data = self.connect('delete', 'nodes/%s/qemu/%s/firewall/ipset/%s' % (self.node, vmid, name), None)
        return data

    def listFirewallIpsetCidr(self, vmid, name, cidr):
        """
        Read IP or Network settings from IPSet
        :param vmid:
        :param name:
        :param cidr:
        :return:
        """
        data = self.connect('get', 'nodes/%s/qemu/%s/firewall/ipset/%s/%s' % (self.node, vmid, name, cidr), None)
        return data

    def editFirewallIpsetCidr(self, vmid, name, cidr, post_data=None):
        """
        Read IP or Network settings from IPSet
        :param vmid:
        :param name:
        :param cidr:
        :return:
        """
        data = self.connect('put', 'nodes/%s/qemu/%s/firewall/ipset/%s/%s' % (self.node, vmid, name, cidr), post_data)
        return data

    def deleteFirewallIpsetCidr(self, vmid, name, cidr):
        """
        Read IP or Network settings from IPSet
        :param vmid:
        :param name:
        :param cidr:
        :return:
        """
        data = self.connect('delete', 'nodes/%s/qemu/%s/firewall/ipset/%s/%s' % (self.node, vmid, name, cidr), None)
        return data

    def listFirewallRules(self, vmid):
        """

        :param vmid:
        :return:
        """
        data = self.connect('get', 'nodes/%s/qemu/%s/firewall/rules' % (self.node, vmid), None)
        return data

    def postFirewallRules(self, vmid, post_data=None):
        """
        Create new rule
        :param vmid:
        :return:
        """
        data = self.connect('post', 'nodes/%s/qemu/%s/firewall/rules' % (self.node, vmid), post_data)
        return data

    def listFirewallRules(self, vmid, pos):
        """
        Get single rule data.
        :param vmid:
        :param pos:
        :return:
        """
        data = self.connect('get', 'nodes/%s/qemu/%s/firewall/rules/%s' % (self.node, vmid, pos), None)
        return data

    def putFirewallRules(self, vmid, pos, post_data=None):
        """
        Modify rule data.
        :param vmid:
        :param pos:
        :return:
        """
        data = self.connect('put', 'nodes/%s/qemu/%s/firewall/rules/%s' % (self.node, vmid, pos), post_data)
        return data

    def listFirewallRules(self, vmid, pos):
        """
        Delete rule.
        :param vmid:
        :param pos:
        :return:
        """
        data = self.connect('delete', 'nodes/%s/qemu/%s/firewall/rules/%s' % (self.node, vmid, pos), None)
        return data

    def readFirewallLog(self, vmid):
        """
        Read Firewall Logs
        :param vmid:
        :return:
        """
        data = self.connect('get', 'nodes/%s/qemu/%s/firewall/log' % (self.node, vmid), None)
        return data

    def getFirewallOptions(self, vmid):
        """
        Get VM Firewall options
        :param vmid:
        :return:
        """
        data = self.connect('get', 'nodes/%s/qemu/%s/firewall/options' % (self.node, vmid), None)
        return data

    def putFirewallOptions(self, vmid, post_data=None):
        """
        Get VM Firewall options
        :param vmid:
        :return:
        """
        data = self.connect('put', 'nodes/%s/qemu/%s/firewall/options' % (self.node, vmid), post_data)
        return data

    def listFirewallRefs(self, vmid):
        """
        Lists possible IPSet/Alias reference which are allowed in source/dest properties.
        :param vmid:
        :return:
        """
        data = self.connect('get', 'nodes/%s/qemu/%s/firewall/refs' % (self.node, vmid), None)
        return data


    """ Snapshot Operations"""

    def listKvmSnapshot(self, vmid):
        """
        List all snapshots.
        :param vmid:
        :return:
        """
        data = self.connect('get', 'nodes/%s/qemu/%s/snaoshot' % (self.node, vmid), None)
        return data

    def createSnapshot(self, vmid, post_data=None):
        """
        List all snapshots.
        :param vmid:
        :return:
        """
        data = self.connect('post', 'nodes/%s/qemu/%s/snapshot' % (self.node, vmid), post_data)
        return data

    def getKvmSnapContent(self, vmid, snapname):
        """
        Get snapname content
        :param vmid:
        :param snapname:
        :return:
        """
        data = self.connect('get', 'nodes/%s/qemu/%s/snapshot/%s' % (self.node, vmid, snapname), None)
        return data

    def deleteKvmSnapContent(self, vmid, snapname):
        """
        Delete snapname content
        :param vmid:
        :param snapname:
        :return:
        """
        data = self.connect('delete', 'nodes/%s/qemu/%s/snapshot/%s' % (self.node, vmid, snapname), None)
        return data

    def getSnapnameConfig(self, vmid, snapname):
        """
        Get snapname Config
        :param vmid:
        :param snapname:
        :return:
        """
        data = self.connect('get', 'nodes/%s/qemu/%s/snapshot/%s/config' % (self.node, vmid, snapname), None)
        return data

    def putSnapnameConfig(self, vmid, snapname, post_data=None):
        """
        Update snapname config
        :param vmid:
        :param snapname:
        :return:
        """
        data = self.connect('put', 'nodes/%s/qemu/%s/snapshot/%s/config' % (self.node, vmid, snapname), post_data)
        return data

    def postSnapnameRollback(self, vmid, snapname):
        """
        Delete snapname content
        :param vmid:
        :param snapname:
        :return:
        """
        data = self.connect('post', 'nodes/%s/qemu/%s/snapshot/%s/rollback' % (self.node, vmid, snapname), None)
        return data

    """ Status Operations """

    def getDirectoryIndex(self, vmid):
        """
        :param vmid:
        :return:
        """
        data = self.connect('get', 'nodes/%s/qemu/%s/status' % (self.node, vmid), None)
        return data

    def getKvmCurrent(self, vmid):
        """
        :param vmid:
        :return data:
        """
        data = self.connect('get', 'nodes/%s/qemu/%s/status/current' % (self.node, vmid), None)
        return data

    def postKvmReset(self, vmid, post_data=None):
        """
        :param vmid:
        :return:
        """
        data = self.connect('post', 'nodes/%s/qemu/%s/status/reset' % (self.node, vmid), post_data)
        return data

    def postKvmResume(self, vmid, post_data=None):
        """
        :param vmid:
        :return:
        """
        data = self.connect('post', 'nodes/%s/qemu/%s/status/resume' % (self.node, vmid), post_data)
        return data

    def postKvmShutdown(self, vmid, post_data=None):
        """
        :param vmid:
        :return:
        """
        data = self.connect('post', 'nodes/%s/qemu/%s/status/shutdown' % (self.node, vmid), post_data)
        return data

    def postKvmStart(self, vmid, post_data=None):
        """
        :param vmid:
        :return:
        """
        data = self.connect('post', 'nodes/%s/qemu/%s/status/start' % (self.node, vmid), post_data)
        return data

    def postKvmStop(self, vmid, post_data=None):
        """
        :param vmid:
        :return:
        """
        data = self.connect('post', 'nodes/%s/qemu/%s/status/stop' % (self.node, vmid), post_data)
        return data

    def postKvmSuspend(self, vmid, post_data=None):
        """
        :param vmid:
        :return:
        """
        data = self.connect('post', 'nodes/%s/qemu/%s/status/suspend' % (self.node, vmid), post_data)
        return data

    """ Other KVM Operations"""

    def postKvmAgent(self, vmid, post_data=None):
        """
        :param vmid:
        :param post_data:
        :return:
        """
        data = self.connect('post', 'nodes/%s/qemu/%s/agent' % (self.node, vmid), post_data)
        return data

    def postKvmClone(self, vmid , post_data=None):
        """
        :param vmid:
        :param post_data:
        :return:
        """
        data = self.connect('post', 'nodes/%s/qemu/%s/clone' % (self.node, vmid), post_data)
        return data

    def getKvmConfig(self, vmid):
        """
        :param vmid:
        :return:
        """
        data = self.connect('get', 'nodes/%s/qemu/%s/config' % (self.node, vmid), None)
        return data

    def postKvmCreateConfig(self, vmid , post_data=None):
        """
        Set virtual machine options
        :param vmid:
        :param post_data:
        :return:
        """
        data = self.connect('post', 'nodes/%s/qemu/%s/config' % (self.node, vmid), post_data)
        return data

    def putKvmConfig(self, vmid, post_data=None):
        """
        Set virtual machine options (synchrounous API) - You should consider using the POST method instead for any actions involving hotplug or storage allocation.
        :param vmid:
        :param post_data:
        :return:
        """
        data = self.connect('put', 'nodes/%s/qemu/%s/config' % (self.node, vmid), post_data)
        return data

    def getKvmFeature(self, vmid):
        """
        Check if feature for virtual machine is available.
        :param vmid:
        :return:
        """
        data = self.connect('get', 'nodes/%s/qemu/%s/feature' % (self.node, vmid), None)
        return data

    def postKvmMigrate(self, vmid, post_data=None):
        """
        Migrate virtual machine. Creates a new migration task.
        :param vmid:
        :param post_data:
        :return:
        """
        data = self.connect('post', 'nodes/%s/qemu/%s/migrate' % (self.node, vmid), post_data)
        return data

    def postKvmMonitor(self, vmid, post_data=None):
        """
        Execute Qemu monitor commands.
        :param vmid:
        :param post_data:
        :return:
        """
        data = self.connect('post', 'nodes/%s/qemu/%s/monitor' % (self.node, vmid), post_data)
        return data

    def postKvmMoveDisk(self, vmid, post_data=None):
        """
        Execute Qemu monitor commands.
        :param vmid:
        :param post_data:
        :return:
        """
        data = self.connect('post', 'nodes/%s/qemu/%s/move_disk' % (self.node, vmid), post_data)
        return data

    def getKvmPendingChanges(self, vmid):
        """
        Get virtual machine configuration, including pending changes.
        :param vmid:
        :return:
        """
        data = self.connect('get', 'nodes/%s/qemu/%s/pending' % (self.node, vmid), None)
        return data

    def putKvmResize(self, vmid, post_data=None):
        """

        :param vmid:
        :param post_data:
        :return:
        """
        data = self.connect('put', 'nodes/%s/qemu/%s/resize' % (self.node, vmid), post_data)
        return data

    def getKvmRRD(self, vmid):
        """Read VM RRD statistics. Returns JSON"""
        data = self.connect('get', 'nodes/%s/qemu/%s/rrd' % (self.node, vmid), None)
        return data

    def getKvmRRDData(self, vmid):
        """Read VM RRD statistics. Returns JSON"""
        data = self.connect('get', 'nodes/%s/qemu/%s/rrddata' % (self.node, vmid), None)
        return data

    def putKvmSendKey(self, vmid, post_data=None):
        """
        Send key event to virtual machine.
        :param vmid:
        :param post_data:
        :return:
        """
        data = self.connect('put', 'nodes/%s/qemu/%s/sendkey' % (self.node, vmid), post_data)
        return data

    def postKvmSpiceProxy(self, vmid, post_data=None):
        """
        Returns a SPICE configuration to connect to the VM.
        :param vmid:
        :param post_data:
        :return:
        """
        data = self.connect('put', 'nodes/%s/qemu/%s/spiceproxy' % (self.node, vmid), post_data)
        return data

    def postCreateKvmTemplate(self, vmid, post_data=None):
        """
        Create a Template.
        :param vmid:
        :param post_data:
        :return:
        """
        data = self.connect('post', 'nodes/%s/qemu/%s/template' % (self.node, vmid), post_data)
        return data

    def putUnlinkKvmDiskImages(self, vmid, post_data=None):
        """
        Unlink/delete disk images.
        :param vmid:
        :param post_data:
        :return:
        """
        data = self.connect('put', 'nodes/%s/qemu/%s/unlink' % (self.node, vmid), post_data)
        return data

    def postKvmVncProxy(self, vmid, post_data=None):
        """
        Creates a VNC Proxy for a virtual machine. Returns JSON
        :param vmid:
        :param post_data:
        :return:
        """
        data = self.connect('post', "nodes/%s/qemu/%s/vncproxy" % (self.node, vmid), post_data)
        return data

    def getWebSocketTraffic(self, vmid):
        """
        Opens a weksocket for VNC traffic.
        :param vmid:
        :return:
        """
        data = self.connect('get', "nodes/%s/qemu/%s/vncwebsocket" % (self.node, vmid), None)
        return data