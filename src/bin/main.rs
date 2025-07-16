#![no_std]
#![no_main]
#![feature(type_alias_impl_trait)]
#![feature(impl_trait_in_assoc_type)]

use embassy_executor::Spawner;
use embassy_time::{Duration, Timer, with_timeout};
use esp_backtrace as _;
use esp_hal::{
    rng::Rng,
    clock::CpuClock,
};
use esp_wifi::{
    init,
    wifi::{ClientConfiguration, Configuration, WifiController, WifiDevice, WifiEvent, WifiState},
    EspWifiController,
};
use esp_hal::timer::timg::TimerGroup;
use log::{debug, error, info};
use embassy_net::{
    tcp::TcpSocket,
    Runner,
    {dns::DnsQueryType, StackResources},
};
use rust_mqtt::{
    client::{client::MqttClient, client_config::ClientConfig},
    packet::v5::reason_codes::ReasonCode,
    utils::rng_generator::CountingRng,
};
use hmac_sha256::HMAC;
use esp_mbedtls::{asynch::Session, Certificates, Mode, TlsVersion};
use esp_mbedtls::{Tls, X509};

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::ffi::CString;

// This creates a default app-descriptor required by the esp-idf bootloader.
// For more information see: <https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/system/app_image_format.html#application-description>
esp_bootloader_esp_idf::esp_app_desc!();

const SSID: &str = env!("SSID");
const PASSWORD: &str = env!("PASSWORD");

const PRODUCTEKY: &str = env!("PRODUCTEKY");
const DEVICENAME: &str = env!("DEVICENAME");
const DEVICESECRET: &str = env!("DEVICESECRET");

macro_rules! mk_static {
    ($t:ty,$val:expr) => {{
        static STATIC_CELL: static_cell::StaticCell<$t> = static_cell::StaticCell::new();
        #[deny(unused_attributes)]
        let x = STATIC_CELL.uninit().write(($val));
        x
    }};
}

#[esp_hal_embassy::main]
async fn main(spawner: Spawner) {
    // generator version: 0.4.0

    esp_println::logger::init_logger_from_env();

    let config = esp_hal::Config::default().with_cpu_clock(CpuClock::max());
    let peripherals = esp_hal::init(config);

    esp_alloc::heap_allocator!(size: 96 * 1024);

    let timg0 = TimerGroup::new(peripherals.TIMG0);
    let mut rng = Rng::new(peripherals.RNG);
    
    let esp_wifi_ctrl = &*mk_static!(
        EspWifiController<'static>,
        init(timg0.timer0, rng.clone(), peripherals.RADIO_CLK).unwrap()
    );

    let (controller, interfaces) = esp_wifi::wifi::new(&esp_wifi_ctrl, peripherals.WIFI).unwrap();

    let wifi_interface = interfaces.sta;

    let timg1 = TimerGroup::new(peripherals.TIMG1);
    esp_hal_embassy::init(timg1.timer0);

    let ip_config = embassy_net::Config::dhcpv4(Default::default());

    let seed = (rng.random() as u64) << 32 | rng.random() as u64;

    // Init network stack
    let (stack, runner) = embassy_net::new(
        wifi_interface,
        ip_config,
        mk_static!(StackResources<3>, StackResources::<3>::new()),
        seed,
    );

    spawner.spawn(connection(controller)).ok();
    spawner.spawn(net_task(runner)).ok();

    let mut rx_buffer: [u8; 4096] = [0; 4096];
    let mut tx_buffer: [u8; 4096] = [0; 4096];

    //wait until wifi connected
    loop {
        if stack.is_link_up() {
            break;
        }
        Timer::after(Duration::from_millis(500)).await;
    }

    info!("Waiting to get IP address...");
    loop {
        if let Some(ip_config) = stack.config_v4() {
            info!("Got IP: {}", ip_config.address); //dhcp IP address
            break;
        }
        Timer::after(Duration::from_millis(500)).await;
    }

    let mut tls = Tls::new(peripherals.SHA)
        .unwrap()
        .with_hardware_rsa(peripherals.RSA);

    tls.set_debug(0);

    loop {
        Timer::after(Duration::from_millis(1_000)).await;

        let timestamp = (2524608000000 + esp_hal::time::Instant::now().duration_since_epoch().as_micros()).to_string();

        let host = PRODUCTEKY.to_string() + ".iot-as-mqtt.cn-shanghai.aliyuncs.com";
        let user_name: String = DEVICENAME.to_string() + "&" + PRODUCTEKY;
        let client_id = PRODUCTEKY.to_string() + "." + DEVICENAME;
        let extended_client_id = PRODUCTEKY.to_string() + "." + DEVICENAME + "|timestamp=" + &timestamp + ",lan=RUST,_v=1.0.0,securemode=2,signmethod=hmacsha256,ext=3|";
        let sign_src = "clientId".to_string() + &client_id + "deviceName" + DEVICENAME + "productKey" + PRODUCTEKY + "timestamp" + &timestamp;
        static SECRETLEN: usize = DEVICESECRET.len();
        let mut device_secret: [u8;SECRETLEN] = [0;SECRETLEN];
        for i in 0..SECRETLEN { device_secret[i] = DEVICESECRET.as_bytes()[i]; }
        let password = HMAC::mac(&sign_src.into_bytes(), device_secret);
        let passwd_str = to_hex(&password); 
        let c_host = CString::new(host.as_str()).unwrap();
        let server_name = c_host.as_c_str();

        let mut socket = TcpSocket::new(stack, &mut rx_buffer, &mut tx_buffer);

        let address = match stack
            .dns_query(&host, DnsQueryType::A)
            .await
            .map(|a| a[0])
        {
            Ok(address) => address,
            Err(e) => {
                error!("DNS lookup error: {e:?}");
                continue;
            }
        };

        let remote_endpoint = (address, 8883);
        info!("connecting...");
        let tcp_connection = socket.connect(remote_endpoint).await;
        if let Err(e) = tcp_connection {
            error!("connect error: {:?}", e);
            continue;
        }
        info!("connected!");

        let certificates = Certificates {
            ca_chain: X509::pem(
                concat!(include_str!("./ali_iot_ca.crt"), "\0").as_bytes(),
            )
            .ok(),
            ..Default::default()
        };

        let mut session = Session::new(
            socket,
            Mode::Client {
                servername: server_name,
            },
            TlsVersion::Tls1_3,
            certificates,
            tls.reference(),
        )
        .unwrap();

        info!("Start tls connect");
        session.connect().await.unwrap();

        info!("tls connected!");

        let mut mqtt_config = ClientConfig::new(
            rust_mqtt::client::client_config::MqttVersion::MQTTv5,
            CountingRng(20000),
        );
        mqtt_config.keep_alive = 300;
        mqtt_config.add_max_subscribe_qos(rust_mqtt::packet::v5::publish_packet::QualityOfService::QoS1);
        mqtt_config.add_username(&user_name);
        mqtt_config.add_password(&passwd_str);
        mqtt_config.add_client_id(&extended_client_id);
        mqtt_config.max_packet_size = 4096;
        let mut recv_buffer = [0; 4096];
        let mut write_buffer = [0; 4096];

        let mut client: MqttClient<'_, Session<'_, TcpSocket<'_>>, 5, CountingRng> =
            MqttClient::<_, 5, _>::new(session, &mut write_buffer, 4096, &mut recv_buffer, 4096, mqtt_config);

        match client.connect_to_broker().await {
            Ok(()) => {}
            Err(mqtt_error) => match mqtt_error {
                ReasonCode::NetworkError => {
                    error!("MQTT Network Error");
                    Timer::after(Duration::from_millis(5000)).await;
                    continue;
                }
                _ => {
                    error!("Other MQTT Error: {:?}", mqtt_error);
                    Timer::after(Duration::from_millis(5000)).await;
                    continue;
                }
            },
        }

        let sub_topic = "/sys/".to_string() + PRODUCTEKY + "/" + DEVICENAME + "/thing/event/property/post_reply";
        match client.subscribe_to_topic(&sub_topic).await{
            Ok(()) => {info!("sub succes!");}
            Err(mqtt_error) => match mqtt_error {
                ReasonCode::NetworkError => {
                    error!("sub MQTT Network Error");
                    Timer::after(Duration::from_millis(5000)).await;
                    continue;
                }
                _ => {
                    error!("sub Other MQTT Error: {:?}", mqtt_error);
                    Timer::after(Duration::from_millis(5000)).await;
                    continue;
                }
            },
        }

        let pub_topic: String = "/sys/".to_string() + PRODUCTEKY + "/" + DEVICENAME + "/thing/event/property/post";
        let mut count: u32 = 0;
        loop {
            info!("count: {}", count);
            if count % 60 == 0 {
                match client.send_message(
                    &pub_topic,
                    "{\"params\":{\"PowerSwitch\":0},\"version\":\"1.0\"}".as_bytes(),
                    rust_mqtt::packet::v5::publish_packet::QualityOfService::QoS1,
                    true,
                ).await {
                    Ok(()) => {info!("pub succes!");}
                    Err(mqtt_error) => match mqtt_error {
                        ReasonCode::NetworkError => {
                            error!("pub MQTT Network Error");
                            Timer::after(Duration::from_millis(5000)).await;
                            break;
                        }
                        _ => {
                            error!("pub Other MQTT Error: {:?}", mqtt_error);
                            Timer::after(Duration::from_millis(5000)).await;
                            break;
                        }
                    },
                }
            }

            match with_timeout(Duration::from_millis(1000), client.receive_message()).await.ok() {
                Some(Ok((topic, message))) => {
                    let message_str = core::str::from_utf8(message).unwrap_or("<Invalid UTF-8>");
                    info!("Received message on topic {:#?}: {:#?}", topic, message_str);
                    Timer::after(Duration::from_millis(1000)).await;
                }
                Some(Err(mqtt_error)) => match mqtt_error {
                    ReasonCode::NetworkError => {
                        info!("rec MQTT Network Error - Client Messsage Receive Error");
                        Timer::after(Duration::from_millis(5000)).await;
                        break;
                    }
                    _ => {
                        info!("rec Other MQTT Error: {:?}", mqtt_error);
                        Timer::after(Duration::from_millis(5000)).await;
                        break;
                    }
                }
                None => {}
            }
            count += 1;
        }
    }

    // for inspiration have a look at the examples at https://github.com/esp-rs/esp-hal/tree/esp-hal-v1.0.0-beta.1/examples/src/bin
}

// maintains wifi connection, when it disconnects it tries to reconnect
#[embassy_executor::task]
async fn connection(mut controller: WifiController<'static>) {
    info!("start connection task");
    debug!("Device capabilities: {:?}", controller.capabilities());
    loop {
        match esp_wifi::wifi::wifi_state() {
            WifiState::StaConnected => {
                // wait until we're no longer connected
                controller.wait_for_event(WifiEvent::StaDisconnected).await;
                Timer::after(Duration::from_millis(5000)).await
            }
            _ => {}
        }
        if !matches!(controller.is_started(), Ok(true)) {
            let client_config = Configuration::Client(ClientConfiguration {
                ssid: SSID.try_into().unwrap(),
                password: PASSWORD.try_into().unwrap(),
                ..Default::default()
            });
            controller.set_configuration(&client_config).unwrap();
            info!("Starting wifi");
            controller.start_async().await.unwrap();
            info!("Wifi started!");
        }
        info!("About to connect...");

        match controller.connect_async().await {
            Ok(_) => info!("Wifi connected!"),
            Err(e) => {
                error!("Failed to connect to wifi: {e:?}");
                Timer::after(Duration::from_millis(5000)).await
            }
        }
    }
}

// A background task, to process network events - when new packets, they need to processed, embassy-net, wraps smoltcp
#[embassy_executor::task]
async fn net_task(mut runner: Runner<'static, WifiDevice<'static>>) {
    runner.run().await
}

static HEX_TABLE :[char;16] = ['0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F'];
fn to_hex(data : impl AsRef<[u8]>) -> String {
    let data = data.as_ref();
    let len = data.len();
    let mut res = String::with_capacity(len * 2);

    for i in 0..len {
        res.push(HEX_TABLE[usize::from(data[i] >> 4)] );
        res.push(HEX_TABLE[usize::from(data[i] & 0x0F)]);
    }
    res
}