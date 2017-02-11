#!/usr/bin/python

from core import pycore

session = pycore.Session(persistent=True)
node1 = session.addobj(cls=pycore.nodes.CoreNode, name="n1")
node2 = session.addobj(cls=pycore.nodes.CoreNode, name="n2")
hub1 = session.addobj(cls=pycore.nodes.HubNode, name="hub1")
# rj1 = session.addobj(cls=pycore.nodes.RJ45Node, name="dummy0")
node1.newnetif(hub1, ["10.0.0.1/24"])
node2.newnetif(hub1, ["10.0.0.2/24"])
# node1.newnetif(rj1, ["10.0.9.1/24"])
node1.nodefilecopy("scrooge", "./scrooge")

# rj1.attachnet("dummy0")

# node1.icmd(["/vagrant/bin/dlv"])

node1.icmd(["ip", "link"])

node1.icmd([
    "./scrooge",
    # "/vagrant/bin/dlv",
    # "exec",
    # "./scrooge",
    # "-l",
    # "10.0.9.1:5050",
    # "--headless",
    # "--",
    "-interface", "eth0",
    "-controlAddress", "10.0.0.1:8000",
    "-publicKey", "LLBQ9vdHBeVsb55NEnRiHFQ71122IvAFk+XT/Szd7VU=",
    "-privateKey", "cEWVkEjpGbx810PI1e2Ff9f95oYayhnWJBPpV9Spd+IssFD290cF5Wxvnk0SdGIcVDvXXbYi8AWT5dP9LN3tVQ==",
    "-tunnelPublicKey", "cRwjM2IXh/NM1Ebjg2lCr4pjTYeI83MI0WBl7zLH3Uk=",
    "-tunnelPrivateKey", "oBWilMRpFOHdfUjPINgc7DnGMuPUItP7mg6MKhu78FI="
])

session.shutdown()

# ./scrooge -interface eth0 -controlAddress 10.0.0.1:8000 -publicKey LLBQ9vdHBeVsb55NEnRiHFQ71122IvAFk+XT/Szd7VU= -privateKey cEWVkEjpGbx810PI1e2Ff9f95oYayhnWJBPpV9Spd+IssFD290cF5Wxvnk0SdGIcVDvXXbYi8AWT5dP9LN3tVQ== -tunnelPublicKey cRwjM2IXh/NM1Ebjg2lCr4pjTYeI83MI0WBl7zLH3Uk= -tunnelPrivateKey oBWilMRpFOHdfUjPINgc7DnGMuPUItP7mg6MKhu78FI=
