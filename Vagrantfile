Vagrant.configure("2") do |config|
  config.vagrant.plugins = "vagrant-libvirt"
  config.vm.box = "generic/debian12"
  config.vm.provider "libvirt"

  config.vm.provider :libvirt do |libvirt|
    libvirt.driver = "kvm"
    libvirt.uri = "qemu:///system"
    libvirt.cpus = 2
    libvirt.memory = 2048
  end

  config.vm.define "ion" do |ion|
    ion.vm.provider :libvirt do |libvirt|
      libvirt.cpus = 2
      libvirt.memory = 2048
    end
    ion.vm.synced_folder ".", "/vagrant", type: "nfs", nfs_version: 4, nfs_udp: false, mount_options: ['tcp', 'nolock']
    ion.vm.network :private_network, :ip => "192.168.50.10", :libvirt__netmask => "255.255.255.0"
    ion.vm.hostname = "ion-node"
    ion.vm.provision "file", source: "configs/host.ionconfig", destination: "$HOME/host.ionconfig"
    ion.vm.provision "file", source: "configs/host.rc", destination: "$HOME/host.rc"
    ion.vm.provision "shell", inline: <<-EOF
    apt-get update
    apt-get install -y curl git ca-certificates make pkg-config libnl-genl-3-dev libevent-dev build-essential linux-headers-generic #linux-headers-$(uname -r)
    
    wget -q https://github.com/nasa-jpl/ION-DTN/archive/refs/tags/ion-open-source-4.1.3.tar.gz
    tar -zxf ion-open-source-4.1.3.tar.gz
    cd ION-DTN-ion-open-source-4.1.3
    make
    make install
    EOF
  end

  config.vm.define "ud3tn" do |ud3tn|
    ud3tn.vm.provider :libvirt do |libvirt|
      libvirt.cpus = 2
      libvirt.memory = 2048
    end
    ud3tn.vm.synced_folder ".", "/vagrant", disable: true
    ud3tn.vm.network :private_network, :ip => "192.168.50.20", :libvirt__netmask => "255.255.255.0"
    ud3tn.vm.hostname = "ud3tn-node"
    ud3tn.vm.provision "shell", inline: <<-EOF
    apt-get update
    apt-get install -y curl git curl ca-certificates make build-essential libsqlite3-dev sqlite3 python3.11-venv

    git clone --recursive https://gitlab.com/d3tn/ud3tn.git	
    cd ud3tn
    make posix -j8
    make virtualenv
    source .venv/bin/activate
    make update-virtualenv
    EOF
  end
end
