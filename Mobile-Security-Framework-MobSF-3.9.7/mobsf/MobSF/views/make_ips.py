import scapy.all as scapy
import re

def load_common_ips(config_file):
    common_ips = []
    with open(config_file, 'r') as f:
        for line in f:
            ip_pattern = line.strip().replace('.', r'\.').replace('*', r'.*')
            common_ips.append(re.compile(r'^' + ip_pattern + r'$'))
    return common_ips

def is_local_ip(ip):
    # 本地IP范围
    local_ip_patterns = [
        re.compile(r"^10\..*"),
        re.compile(r"^172\.(1[6-9]|2[0-9]|3[0-1])\..*"),
        re.compile(r"^192\.168\..*")
    ]
    
    for pattern in local_ip_patterns:
        if pattern.match(ip):
            return True
    return False

def is_common_ip(ip, common_ip_patterns):
    for pattern in common_ip_patterns:
        if pattern.match(ip):
            return True
    return False

def extract_and_save_ips_from_pcap(pcap_file, common_ip_patterns, output_file):
    try:
        packets = scapy.rdpcap(pcap_file)
    except Exception as e:
        return f"读取 pcap 文件 {pcap_file} 时出错: {e}"

    ips = set()
    
    try:
        for packet in packets:
            if packet.haslayer(scapy.IP):
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                
                if not (is_local_ip(src_ip) or is_common_ip(src_ip, common_ip_patterns)):
                    ips.add(src_ip)
                if not (is_local_ip(dst_ip) or is_common_ip(dst_ip, common_ip_patterns)):
                    ips.add(dst_ip)
    except Exception as e:
        return f"处理数据包时出错: {e}"
        return

    try:
        with open(output_file, 'w') as f:
            for ip in ips:
                f.write(ip + '\n')
        return f"唯一的非本地 IP 已保存到 {output_file}"
    except Exception as e:
        return f"写入文件 {output_file} 时出错: {e}"

