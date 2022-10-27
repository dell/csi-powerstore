
# supress ginkgo 2.0 upgrade hints
export ACK_GINKGO_DEPRECATIONS=1.16.5

# run all tests 
go test -timeout=25m -v ./ -ginkgo.v=1

