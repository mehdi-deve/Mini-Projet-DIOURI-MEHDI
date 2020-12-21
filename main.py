from scapy.all import *
from fastapi import FastAPI, File, UploadFile,Form
from fastapi.encoders import jsonable_encoder
import uvicorn



def parse_pcap_file(file_name):
    packets = rdpcap(file_name)
    res={}
    data=[]
    # Let's iterate through every packet
    for packet in packets:
        res={
            'Ethernet':
            {
            'dst':'{}'.format(packet.sprintf("%Ether.dst%")),
            'src':'{}'.format(packet.sprintf("%Ether.src%")),
            'type':'{}'.format(packet.sprintf("%Ether.type%"))
            },
            'ARP':
            {
                'hwtype':'{}'.format(packet.sprintf("%ARP.hwtype%")),
                'ptype':'{}'.format(packet.sprintf("%ARP.ptype%")),
                'hwlen':'{}'.format(packet.sprintf("%ARP.hwlen%")),
                'plen':'{}'.format(packet.sprintf("%ARP.plen%")),
                'op':'{}'.format(packet.sprintf("%ARP.op%")),
                'hwsrc':'{}'.format(packet.sprintf("%ARP.hwsrc%")),
                'psrc':'{}'.format(packet.sprintf("%ARP.psrc%")),
                'hwdst':'{}'.format(packet.sprintf("%ARP.hwdst%")),
                'pdst':'{}'.format(packet.sprintf("%ARP.pdst%"))
            },
            'Padding':
            {
                'load':'{}'.format(packet.sprintf("%Padding.load%"))
            }
        }
        data.append(res)
    return data

app = FastAPI()

@app.route("/")
@app.get("/")
async def root():
    return {"Deep Packet Inspection Service ARP "}
@app.post("/file_metadata/")
async def create_upload_file(file: UploadFile = File(...)):
    file_name=file.filename
    file.save('./{}'.format(file_name))
    packets = rdpcap('./{}'.format(file_name))
    res={}
    data=[]
    # Let's iterate through every packet
    for packet in packets:
        res={
            'Ethernet':
            {
            'dst':'{}'.format(packet.sprintf("%Ether.dst%")),
            'src':'{}'.format(packet.sprintf("%Ether.src%")),
            'type':'{}'.format(packet.sprintf("%Ether.type%"))
            },
            'ARP':
            {
                'hwtype':'{}'.format(packet.sprintf("%ARP.hwtype%")),
                'ptype':'{}'.format(packet.sprintf("%ARP.ptype%")),
                'hwlen':'{}'.format(packet.sprintf("%ARP.hwlen%")),
                'plen':'{}'.format(packet.sprintf("%ARP.plen%")),
                'op':'{}'.format(packet.sprintf("%ARP.op%")),
                'hwsrc':'{}'.format(packet.sprintf("%ARP.hwsrc%")),
                'psrc':'{}'.format(packet.sprintf("%ARP.psrc%")),
                'hwdst':'{}'.format(packet.sprintf("%ARP.hwdst%")),
                'pdst':'{}'.format(packet.sprintf("%ARP.pdst%"))
            },
            'Padding':
            {
                'load':'{}'.format(packet.sprintf("%Padding.load%"))
            }
        }
        data.append(res)
    return data


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=5000, log_level="info")
