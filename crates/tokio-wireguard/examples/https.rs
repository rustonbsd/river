use std::{net::{Ipv4Addr, SocketAddr}, str::FromStr, time::Duration};

use bytes::BufMut as _;
use tokio::{io::{AsyncReadExt as _, AsyncWriteExt as _}, time::sleep};
use tokio_wireguard::wireguard::WireGuardProxyConfig;


#[tokio::main]
async fn main() {
    let wg_config_str = r#"[Interface]
PrivateKey = 8LabAQS1FjgLtWnlv8vyK0cpxK+kIq/fotdyM1ZtiX4=
Address = 10.0.0.2/24
DNS = 10.0.0.4

[Peer]
PublicKey = ePum20nqg6F+K20L7FR5AChCozZmJCIOUVp0+HupaHM=
AllowedIPs = 0.0.0.0/0
Endpoint = 5.161.182.74:51820
PersistentKeepalive = 25
"#;
    let req_text = r#"GET / HTTP/1.1
Host: developtheworld.de
Connection: keep-alive
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en-DE;q=0.9,en;q=0.8

"#.as_bytes();



    let proxy = WireGuardProxyConfig::from_str(&wg_config_str).unwrap();
    let mut client = proxy
    .connect_addr(SocketAddr::new(
        std::net::IpAddr::V4(Ipv4Addr::from_str(&"168.119.249.56").unwrap()),
        6969u16,
    ))
    .await
    .unwrap();

    //let (mut read, mut write) = client.into_split();
    
    loop {
        let send = client.write(req_text).await.unwrap();
        println!("SEND:  {:?}",send);

        let mut msg: Vec<u8> = vec![0;1024];

        let mut msg2 = vec![0;1024];
        //println!("Starting to read! {:?}",client.readable().await.unwrap());
        //println!("{:?}",client.peek(msg).await.unwrap());
        let resp = client.read(&mut msg2).await.unwrap();
        let t = msg.remaining_mut();
        println!("Remaining: {t}");
        
        println!("RESP:  {} {}",resp,String::from_utf8_lossy(&msg2));
        sleep(Duration::from_secs(2)).await;
    }

    /*
    let mut stdin = BufReader::new(tokio::io::stdin()).lines();
    while let Some(mut message) = stdin.next_line().await.unwrap() {
        if message == ".exit" {
            break;
        }

        message.push('\n');
        client.write_all(message.as_bytes()).await.unwrap();
    }*/
}
