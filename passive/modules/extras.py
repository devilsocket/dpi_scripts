import os

def logo():
	data = ""
	lpath = os.path.join(os.getcwd(),'modules','logo.txt')
	if os.path.exists(lpath):
		with open(lpath, 'r') as lg:
			data = str(lg.read())
	return data
