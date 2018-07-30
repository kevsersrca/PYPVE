# PYPVE Proxmox Virtual Environment 5 API Client

Proxmox Virtual Environment is an open source server virtualization management solution based on QEMU/KVM and LXC. You can manage virtual machines, containers, highly available clusters, storage and networks with an integrated, easy-to-use web interface or via CLI. Proxmox VE code is licensed under the GNU Affero General Public License, version 3.
Doc link : https://pve.proxmox.com/wiki/Main_Page

## Getting Started

```
client = pypve('node1.example.com','client@pve','password')
client.node = 'pve'
getIndex = client.getKvmIndex()

```

### Prerequisites

Modules

```
sys
requests
json
```

### Installing

Via git


## Contributing

Please read CONTRIBUTING for details on our code of conduct, and the process for submitting pull requests to us.


## Authors

* **Kevser SIRCA** - *Devops Engineer* - [Kevsersrca](https://github.com/kevsersrca)


## License

This project is licensed under the MIT License - see the [LICENSE.md](LICENSE.md) file for details



