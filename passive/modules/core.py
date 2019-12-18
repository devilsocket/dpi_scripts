from dpkt.pcap import Reader
from dpkt.ethernet import Ethernet, ETH_TYPE_IP
from dpkt.ip import IP_PROTO_TCP, IP_PROTO_UDP
from dpkt.dns import DNS
from dpkt.tcp import TH_FIN, TH_SYN, TH_RST, TH_PUSH, TH_ACK, TH_URG, TH_ECE, TH_CWR
from socket import inet_ntoa
from datetime import datetime
from dpkt.dpkt import UnpackError
from pprint import pprint
import os

def DnsRequestParser(udp):
	res = {}
	dns = False
	try:dns = DNS(udp.data)
	except (UnpackError):pass
	if dns:
		if 'qd' in dns.__hdr_fields__:
			if dns.qd:
				res['domain'] = dns.qd[0].name.__str__()
				res['type'] = 'dns_request'
	return res

def DnsResponseParser(udp):
	res = {}
	dns = False
	try:dns = DNS(udp.data)
	except (UnpackError):pass
	if dns:
		if 'qd' in dns.__hdr_fields__:
			if dns.qd:
				res['domain'] = dns.qd[0].name.__str__()
				res['type'] = 'dns_response'
				res['answers'] = []
				if 'an' in dns.__hdr_fields__:
					for answer in dns.an:
						if answer.type == 1:
							res['answers'].append(
									{
										'answer' : answer.name.__str__(),
										'ip' : inet_ntoa(answer.ip)
									}
								)
	return res

def flagScanner(tcp):
	result = []
	if ( tcp.flags & TH_FIN ) != 0:
		result.append('fin')
	if ( tcp.flags & TH_SYN ) != 0:
		result.append('syn')
	if ( tcp.flags & TH_RST ) != 0:
		result.append('rst')
	if ( tcp.flags & TH_PUSH ) != 0:
		result.append('psh')
	if ( tcp.flags & TH_ACK ) != 0:
		result.append('ack')
	if ( tcp.flags & TH_URG ) != 0:
		result.append('urg')
	if ( tcp.flags & TH_ECE ) != 0:
		result.append('ece')
	if ( tcp.flags & TH_CWR ) != 0:
		result.append('cwr')
	return result

def passiveSession(pcap_path):
	data = {
		'healthy_sessions' : [],
		'corrupt_sessions' : []
	}
	sessions = {}
	complete = []
	with open(pcap_path,'rb') as pf:
		pcap_file_name = pcap_path
		dpkt_file_object = False
		try:dpkt_file_object = Reader(pf)
		except Exception as err:
			dpkt_file_object = False
			print("[-] pcap corruption detected : {}".format(pcap_path))
		if dpkt_file_object:
			print("[+] pcap's health fine : {}".format(pcap_path))
			for ts, payload in dpkt_file_object:
				t1, p = ts, payload
				t = datetime.fromtimestamp(t1).strftime("%Y-%m-%d %H:%M:%S")
				eth = False
				try:eth = Ethernet(payload)
				except:eth = False
				if eth:
					if eth.type == 2048:
						ip = eth.data
						src_ip = inet_ntoa(ip.src)
						dst_ip = inet_ntoa(ip.dst)
						if ip.p == 6:
							tcp_pkt_header = False
							tcp = ip.data
							try:tcp_pkt_header = tcp.__hdr__
							except:tcp_pkt_header = False
							if tcp_pkt_header:
								tcp_packet_data = {}
								tcp_packet_data['pcap_file_name'] = pcap_path.split(os.sep)[-1]
								tcp_packet_data['src_ip'], tcp_packet_data['dst_ip'], tcp_packet_data['pkts_num'] = src_ip, dst_ip, 1
								tcp_src_port, tcp_dst_port = tcp.sport, tcp.dport
								tcp_packet_data['src_port'], tcp_packet_data['dst_port'] = tcp_src_port, tcp_dst_port
								flags = flagScanner(tcp)
								tcp_packet_data['pkts_size'] = tcp.data.__len__()
								uni_key = '{}{}{}{}'.format(tcp_packet_data['src_ip'],tcp_packet_data['src_port'],tcp_packet_data['dst_ip'],tcp_packet_data['dst_port'])
								if 'syn' in flags:
									if uni_key in sessions:del sessions[uni_key]
									tcp_packet_data['start_time'] = t
									tcp_packet_data['end_time'] = t
									tcp_packet_data['session'] = False
									tcp_packet_data['dns_data'] = False
									#if tcp_packet_data['src_ip'] in domains:
									#	tcp_packet_data['dns_data'] = domains[tcp_packet_data['src_ip']]
									#if tcp_packet_data['dst_ip'] in domains:
									#	tcp_packet_data['dns_data'] = domains[tcp_packet_data['dst_ip']]
									sessions[uni_key] = tcp_packet_data
								elif 'fin' in flags:
									if uni_key in sessions:
										sessions[uni_key]['pkts_num']+=tcp_packet_data['pkts_num']
										sessions[uni_key]['pkts_size']+=tcp_packet_data['pkts_size']
										sessions[uni_key]['session'] = True
										sessions[uni_key]['end_time'] = t
										complete_session = sessions[uni_key]
										data["healthy_sessions"].append(complete_session)
										del sessions[uni_key]
								else:
									if uni_key in sessions:
										sessions[uni_key]['pkts_num']+=tcp_packet_data['pkts_num']
										sessions[uni_key]['pkts_size']+=tcp_packet_data['pkts_size']
										sessions[uni_key]['end_time'] = t
	for session in sessions:
		data['corrupt_sessions'].append(sessions[session])
	return data



def passiveDns(pcap_path):
	data = {
		'dns_requests' : [],
		'dns_responses' : []
	}
	sessions = {}
	complete = []
	with open(pcap_path,'rb') as pf:
		pcap_file_name = pcap_path
		dpkt_file_object = False
		try:dpkt_file_object = Reader(pf)
		except Exception as err:
			dpkt_file_object = False
			print("[-] pcap corruption detected : {}".format(pcap_path))
		if dpkt_file_object:
			print("[+] pcap's health fine : {}".format(pcap_path))
			for ts, payload in dpkt_file_object:
				t1, p = ts, payload
				t = datetime.fromtimestamp(t1).strftime("%Y-%m-%d %H:%M:%S")
				eth = False
				try:eth = Ethernet(payload)
				except:eth = False
				if eth:
					if eth.type == 2048:
						ip = eth.data
						src_ip = inet_ntoa(ip.src)
						dst_ip = inet_ntoa(ip.dst)
						if ip.p == 17:
							udp_src_port, udp_dst_port = udp.sport, udp.dport
							if udp_src_port == 53:
								dns_response_data = DnsResponseParser(udp)
								dns_response_data['src_ip'], dns_response_data['dst_ip'] = src_ip, dst_ip
								dns_response_data['src_port'], dns_response_data['dst_port'] = udp_src_port, udp_dst_port
								dns_response_data['dns_time'] = t
								dns_response_data['upload_id'] = upload_id
								data['dns_responses'].append(dns_response_data)
							elif udp_dst_port == 53:
								dns_request_data = DnsRequestParser(udp)
								dns_request_data['src_ip'], dns_request_data['dst_ip'] = src_ip, dst_ip
								dns_request_data['src_port'], dns_request_data['dst_port'] = udp_src_port, udp_dst_port
								dns_request_data['dns_time'] = t
								dns_request_data['upload_id'] = upload_id
								data['dns_requests'].append(dns_request_data)			
	return data