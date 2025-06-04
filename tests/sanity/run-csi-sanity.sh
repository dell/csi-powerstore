csi-sanity --ginkgo.v --csi.controllerendpoint=controller.sock --csi.endpoint=node.sock --csi.testvolumeparameters=params.yaml --ginkgo.junit-report=report.xml 

# to run specific tests, add optional focus arguments like so:
#--ginkgo.focus="should remove target path"
