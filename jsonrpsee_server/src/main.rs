use std::net::SocketAddr;

use jsonrpsee::{
	core::server::access_control::AccessControlBuilder,
	http_server::{HttpServerBuilder, HttpServerHandle, RpcModule},
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
	tracing_subscriber::FmtSubscriber::builder()
		.with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
		.try_init()
		.expect("setting default subscriber failed");

	// Start up a JSONPRC server that allows cross origin requests.
	let (server_addr, _handle) = run_server().await?;

	// Print instructions for testing CORS from a browser.
	println!("Run the following snippet in the developer console in any Website.");
	println!(
		r#"
        fetch("http://{}", {{
            method: 'POST',
            mode: 'cors',
            headers: {{ 'Content-Type': 'application/json' }},
            body: JSON.stringify({{
                jsonrpc: '2.0',
                method: 'say_hello',
                id: 1
            }})
        }}).then(res => {{
            console.log("Response:", res);
            return res.text()
        }}).then(body => {{
            console.log("Response Body:", body)
        }});
    "#,
		server_addr
	);

	futures::future::pending().await
}

async fn run_server() -> anyhow::Result<(SocketAddr, HttpServerHandle)> {
	let acl = AccessControlBuilder::new().allow_all_headers().allow_all_origins().allow_all_hosts().build();

	let server =
		HttpServerBuilder::default().set_access_control(acl).build("127.0.0.1:0".parse::<SocketAddr>()?).await?;

	let mut module = RpcModule::new(());
	module.register_method("say_hello", |_, _| {
		println!("say_hello method called!");
		Ok("Hello there!!")
	})?;

	let addr = server.local_addr()?;
	let server_handle = server.start(module)?;

	Ok((addr, server_handle))
}
