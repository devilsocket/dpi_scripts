from sys import argv
from modules.extras import logo
from modules.core import passiveSession, passiveDns
from pprint import pprint
from json import dumps
import os

CATEGORIES = ["session","dns","meta","media","url","credentials"]
LOGO = logo()


def execute(pcap_file_path,category):
	jso = False
	output_file = os.path.join(os.getcwd(),category+'_'+pcap_file_path.split(os.sep)[-1]+'.json')
	if category=="SESSION":
		sessions = passiveSession(pcap_file_path)
		jso = dumps(sessions)
	if category=="DNS":
		dnss = passiveDns(pcap_file_path)
		jso = dumps(dnss)
	if jso:open(output_file,"w").write(jso);print("[+] output of file {} in categoey {} written to file {}".format(pcap_file_path, category, output_file))



	return 1


if __name__ == "__main__":
	print(LOGO)
	if len(argv)==3:
		pcap_file_path = argv[1]
		category = argv[2]
		execute(pcap_file_path,category)
	else:
		print("[+] supported categories :")
		for category in CATEGORIES:
			print("\t>>>> {}".format(category.upper()))
		print("[+] use command - python {} <pcap_file_path> <category>".format(argv[0]))