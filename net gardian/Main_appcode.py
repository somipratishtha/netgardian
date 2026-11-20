import streamlit as st
import pandas as pd
from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP
from datetime import datetime

st.set_page_config(
    page_title="Net Guardian",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ Net Guardian")
st.subheader("Real-Time Network Traffic Monitoring")

st.info("Prototype mode: Sample data")

data = [
    {
        "Time": "10:00:01",
        "Source IP": "192.168.1.10",
        "Destination IP": "8.8.8.8",
        "Protocol": "UDP",
        "Packet Size": 700,
        "Status": "Normal"
    },
    {
        "Time": "10:00:03",
        "Source IP": "192.168.1.20",
        "Destination IP": "192.168.1.10",
        "Protocol": "TCP",
        "Packet Size": 950,
        "Status": "Normal"
    },
    {
        "Time": "10:00:05",
        "Source IP": "192.168.1.50",
        "Destination IP": "192.168.1.10",
        "Protocol": "TCP",
        "Packet Size": 300,
        "Status": "Review"
    }
]

df = pd.DataFrame(data)

col1, col2, col3 = st.columns(3)

col1.metric("Packets Captured", len(df))
col2.metric("Protocols", df["Protocol"].nunique())
col3.metric("Packets to Review", (df["Status"] == "Review").sum())

st.subheader("Network Packet Information")
st.dataframe(df, use_container_width=True)

st.subheader("Protocol Distribution")
st.bar_chart(df["Protocol"].value_counts())

st.subheader("Activity Alerts")

for _, packet in df[df["Status"] == "Review"].iterrows():
    st.warning(
        f"Packet requires review: {packet['Source IP']} "
        f"to {packet['Destination IP']}"
    )

from scapy.all import sniff


if st.button("Start Live Capture"):

    with st.spinner("Capturing packets..."):
        packets = sniff(count=10, timeout=10, store=True)

    rows = []

    for packet in packets:

        if IP in packet:
            source = packet[IP].src
            destination = packet[IP].dst

        elif IPv6 in packet:
            source = packet[IPv6].src
            destination = packet[IPv6].dst

        else:
            continue

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        elif ICMP in packet:
            protocol = "ICMP"
        else:
            protocol = "Other"

        rows.append({
            "Time": datetime.fromtimestamp(
                float(packet.time)
            ).strftime("%H:%M:%S"),
            "Source IP": source,
            "Destination IP": destination,
            "Protocol": protocol,
            "Packet Size": len(packet),
            "Status": "Captured"
        })

    st.success(f"Captured {len(packets)} packets!")

    if rows:
        live_df = pd.DataFrame(rows)
        st.subheader("Live Network Packet Information")
        st.dataframe(live_df, use_container_width=True)
    else:
        st.warning("No supported IP packets found.")

    with st.spinner("Capturing packets..."):
        packets = sniff(count=10, timeout=10, store=True)

    st.success(f"Captured {len(packets)} packets!")
    st.write(packets.summary())
