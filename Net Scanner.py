import scapy.all as scapy
import optparse

#arp request  mac ve ıp adresi eşleştirmek için
#broadcast  yayın yapmak için ağ içindeki her yere yolluyor
#response

def get_input():

    parse_object = optparse.OptionParser()
    parse_object.add_option("-i","--ipadress",dest="ip_adress",help="Enter ip adress")
    (user_input,arguments) = parse_object.parse_args()

    if not user_input.ip_adress:
        print("Enter ip adress please")

    return user_input

def scan_network(ip):
    arp_request_pack = scapy.ARP(pdst = ip)  #bu sorguyu alttaki adrese gönderecez 256 tane var. bu ıp kimde var diye soruyor
    #scapy.ls(scapy.ARP())  içine verebileceğin inputları gösteriyor
    #"10.0.2.1/24" bunlar arasından bakıyor

    broadcast_pack = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")    #gidilecek olan mac adresi destination modeme yani default tur.
    #scapy.ls(scapy.Ether())                                    #ls komutu gibi orada neler olduğunu gösteriyor, src de biziz gönderen

    combine_pack = broadcast_pack / arp_request_pack  #ikisini kombine ettik çünkü ikisini de kullanıcaz

    (answer_list, unanswer_list) = scapy.srp(combine_pack,timeout=1)
    #içindeki paketi gönderecek cevap verilen verilmeyenleri yazacak timeout cevap yoksa cevap vermesini beklemicek
    #srp bunu yolluyor
    #tuple şeklinde iki tane liste bastırıyor

    answer_list.summary()

user_ip_adress = get_input()
scan_network(user_ip_adress.ip_adress)
