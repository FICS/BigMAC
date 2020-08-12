# BigMAC

<img src=".img/bigmac-logo.png?raw=true" align="left"
     title="BigMAC" width="100">

Extract, process, and query Android security policies from Android firmware. BigMAC is a Python tool that helps analysts understand DAC, MAC (SELinux), and capabilities (CAP) on Android devices. It provides a framework for recovering security policies from firmware images, allowing for scalable policy extraction, and for interactive querying using Prolog. [This was released at USENIX Security'20.](https://www.usenix.org/conference/usenixsecurity20/presentation/hernandez)

<br/>
<p align="center">
<img src=".img/policy-layers-linked.png?raw=true"
     title="BigMAC Overview" width="600">
</p>

## Installation

Clone the main repository:
```
git clone https://github.com/FICS/BigMAC
```

Make a Python 3 virtual environment:
```
cd BigMAC/
virtualenv -p python3 venv
```

Activate the virtual environment (do this for each terminal):
```
source venv/bin/activate
```

Your prompt will now look like:
```
(venv) $
```

Install sefcontext-parser (it's not on pip):
```
git clone https://github.com/jakev/sefcontext-parser
cd sefcontext-parser
python setup.py install
```

Install swi-prolog (8.0.X and above is needed):
```
sudo apt-add-repository ppa:swi-prolog/stable
sudo apt-get update
sudo apt-get install swi-prolog
```

Install libsepol (a different version than distros have is needed):

```
git clone --branch libsepol-2.7 https://github.com/SELinuxProject/selinux.git
```

Install the required build dependencies:
```
sudo apt install build-essential flex bison swig python-dev graphviz libgraphviz-dev pkg-config libaudit-dev
```

Apply the [selinux.patch](selinux.patch) below to selinux to make sure that it will be buildable. Apply the patch like this:

```
$ cd selinux
$ patch -p1 < ../selinux.patch
```

Build a specific libsepol to be able to parse Android sepolicy files:
```
make -j # this may not completely build. as long as sepol is built, continue to install step
sudo make install # you MUST install before building setools
```

Get setools for use in Python:
```
git clone https://github.com/TresysTechnology/setools.git
cd setools
git checkout 856b56accba14 # required to match with libsepol version
```

Apply the [setools.patch](setools.patch) below to setools to make sure that it will be buildable. Apply the patch like this:

```
$ cd setools
$ patch -p1 < ../setools.patch
patching file setup.py
```

Build and install setools.
Make sure the `SEPOL_SRC` points to the correct path:

```
SEPOL_SRC=$(pwd)/../selinux/libsepol/ python3 setup.py build_ext build_py install
```

Go back to the main BigMAC directory and install all pip requirements:
```
BigMAC/ $ pip install -r requirements.txt
```

Try running the process.py main file:
```
$ ./process.py
BigMAC Android Policy Processor
 by Grant Hernandez (https://hernan.de/z)
usage: process.py [-h] --vendor VENDOR [--debug] [--debug-init] [--skip-boot]
                  [--draw-graph] [--focus-set FOCUS_SET] [--save] [--load]
                  [--save-policy] [--list-objects] [--dont-expand-objects]
                  [--prolog]
                  policy_name
process.py: error: the following arguments are required: --vendor, policy_name
```

If you see the usage, all imports are correctly installed. Now move on to the next section to get started.

## Basic Usage

### Policy Processing

Extract out the `eval/eval-policy.tar.gz` file included in the repo for some example policies. For extracting your own from firmware we are working to stream line this process. See the [tools/](tools/) for more information.

To start, process a single image from a vendor and print out the log, but don't save anything. Use this to sanity check your saved policies and policy processing code.
```
./process.py --vendor aosp policy/aosp/sailfish-ppr2.181005.003.a1-factory-dec6298c
./process.py --vendor aosp sailfish-ppr2.181005.003.a1-factory-dec6298c # equivalent to above
```

The saved policies directory is set in the `config.py` file.

If you want to process a policy an interact with the final results using IPython, add the `--debug` flag.

```
./process.py --debug --vendor aosp sailfish-ppr2.181005.003.a1-factory-dec6298c
...
In [0]: inst
Out[0]: <overlay.SEPolicyInst at 0x7ff0a8fd2d30>
```

Try viewing and playing with `inst.processes`, `inst.subjects`, and `inst.objects`!

Processing the entire policy into a graph takes time. The final results can be saved and loaded to speed things up.

```
./process.py --vendor aosp sailfish-ppr2.181005.003.a1-factory-dec6298c --save
./process.py --vendor aosp sailfish-ppr2.181005.003.a1-factory-dec6298c --load --debug # you can load from now on
```

The saved database will be under the firmware specific policy directory under the `db/` sub directory.

To run prolog queries against the policy, add the `--prolog` command. The first time you do this, you will need to compile the prolog helpers.
```
./process.py --vendor aosp sailfish-ppr2.181005.003.a1-factory-dec6298c --load --prolog
query> 
```

Prolog mode will fully instantiate the graph and emit Prolog facts and
binaries. The facts from the last run will be stored in the current directory
under `facts.pl`. This is compiled together with helper functions that will
enable you to query against a static binary of facts, greatly speeding up
queries. These binaries are stored in the `db/` sub directory of the firmware
and can be run manually if you wish.
