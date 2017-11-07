id-qmin.txt: id-qmin.xml
	curl -F input=@id-qmin.xml https://xml2rfc.tools.ietf.org/cgi-bin/xml2rfc.cgi > id-qmin.txt
