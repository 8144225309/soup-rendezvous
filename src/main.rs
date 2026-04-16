use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use nostr_sdk::prelude::*;
use tracing_subscriber::EnvFilter;

use soup_rendezvous::events;
use soup_rendezvous::kinds;

#[derive(Parser)]
#[command(
    name = "soup-rendezvous",
    version,
    about = "Coordination protocol for multi-party Bitcoin signing, built on Nostr."
)]
struct Cli {
    /// Path to the Nostr secret key file (nsec or hex).
    #[arg(long, env = "SOUP_KEY_FILE", default_value = "soup-coordinator.nsec")]
    key_file: PathBuf,

    /// Nostr relay URLs, comma-separated.
    #[arg(
        long,
        env = "SOUP_RELAYS",
        default_value = "wss://relay.damus.io,wss://nos.lol"
    )]
    relays: String,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new coordinator Nostr keypair and save to the key file.
    Init,

    /// Print the coordinator's public key (npub and hex).
    Whoami,

    /// Publish the root discovery thread to the configured relays.
    PublishRoot {
        /// Short description for the root thread.
        #[arg(default_value = "soup-rendezvous: multi-party Bitcoin signing coordination")]
        description: String,
    },

    /// Publish a test factory advertisement (for development).
    TestAd {
        /// The root thread event ID (hex) to reply to.
        root_id: String,

        /// Human-readable name for the factory.
        #[arg(default_value = "test-factory-alpha")]
        name: String,
    },

    /// Publish a status update for a factory.
    UpdateStatus {
        /// The advertisement event ID (hex).
        ad_id: String,

        /// Number of accepted joiners.
        accepted: u32,

        /// Maximum members.
        max_members: u32,

        /// Status message.
        #[arg(default_value = "slots filling up")]
        message: String,
    },

    /// List factory advertisements from the configured relays.
    ListAds {
        /// Only show advertisements replying to this root event ID (hex).
        #[arg(long)]
        root_id: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,soup_rendezvous=debug".into()),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Command::Init => cmd_init(&cli.key_file),
        Command::Whoami => cmd_whoami(&cli.key_file),
        Command::PublishRoot { description } => {
            let keys = load_keys(&cli.key_file)?;
            let client = connect(&cli.relays, &keys).await?;
            cmd_publish_root(&client, &description).await
        }
        Command::TestAd { root_id, name } => {
            let keys = load_keys(&cli.key_file)?;
            let client = connect(&cli.relays, &keys).await?;
            cmd_test_ad(&client, &root_id, &name).await
        }
        Command::UpdateStatus {
            ad_id,
            accepted,
            max_members,
            message,
        } => {
            let keys = load_keys(&cli.key_file)?;
            let client = connect(&cli.relays, &keys).await?;
            cmd_update_status(&client, &ad_id, accepted, max_members, &message).await
        }
        Command::ListAds { root_id } => {
            let keys = load_keys(&cli.key_file)?;
            let client = connect(&cli.relays, &keys).await?;
            cmd_list_ads(&client, root_id.as_deref()).await
        }
    }
}

fn cmd_init(key_file: &PathBuf) -> Result<()> {
    if key_file.exists() {
        bail!(
            "key file already exists at {}, refusing to overwrite",
            key_file.display()
        );
    }
    let keys = Keys::generate();
    let nsec = keys.secret_key().to_bech32()?;
    std::fs::write(key_file, &nsec).context("writing key file")?;
    println!("keypair generated");
    println!("  nsec: {nsec}");
    println!("  npub: {}", keys.public_key().to_bech32()?);
    println!("  hex:  {}", keys.public_key());
    println!("saved to {}", key_file.display());
    Ok(())
}

fn cmd_whoami(key_file: &PathBuf) -> Result<()> {
    let keys = load_keys(key_file)?;
    println!("npub: {}", keys.public_key().to_bech32()?);
    println!("hex:  {}", keys.public_key());
    Ok(())
}

async fn cmd_publish_root(client: &Client, description: &str) -> Result<()> {
    let builder = events::build_root_thread(description);
    let output = client.send_event_builder(builder).await?;
    println!("root thread published");
    println!("  event id: {}", output.id());
    println!("  relays:   {:?}", output.success);
    Ok(())
}

async fn cmd_test_ad(client: &Client, root_id_hex: &str, name: &str) -> Result<()> {
    let root_id = EventId::from_hex(root_id_hex).context("invalid root event id hex")?;

    let payload = events::SuperScalarPayload {
        lsp_pubkey: "02deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(),
        lsp_endpoints: vec!["127.0.0.1:9735".into()],
        lsp_nostr_relays: vec!["wss://relay.damus.io".into()],
        total_funding_sat: "10000000".into(),
        client_contribution_sat: "1000000".into(),
        lsp_liquidity_sat: "2000000".into(),
        leaf_arity: 2,
        epoch_count: 30,
        lifetime_blocks: 4320,
        dying_period_blocks: 432,
        lsp_fee_sat: "5000".into(),
        lsp_fee_ppm: 1000,
    };
    let content = serde_json::to_string_pretty(&payload)?;

    let expiry = Timestamp::now().as_secs() + 7 * 86400;

    let builder = events::build_advertisement(
        &root_id,
        name,
        "superscalar/v1",
        4,
        8,
        &["test", "development"],
        expiry,
        &content,
    );

    let output = client.send_event_builder(builder).await?;
    println!("test advertisement published");
    println!("  event id: {}", output.id());
    println!("  name:     {name}");
    println!("  relays:   {:?}", output.success);
    Ok(())
}

async fn cmd_update_status(
    client: &Client,
    ad_id_hex: &str,
    accepted: u32,
    max_members: u32,
    message: &str,
) -> Result<()> {
    let ad_id = EventId::from_hex(ad_id_hex).context("invalid ad event id hex")?;

    let builder = events::build_status_update(
        &ad_id,
        "superscalar/v1",
        if accepted >= max_members {
            "full"
        } else {
            "filling"
        },
        accepted,
        max_members,
        message,
    );

    let output = client.send_event_builder(builder).await?;
    println!("status update published");
    println!("  event id: {}", output.id());
    println!("  slots:    {accepted}/{max_members}");
    println!("  relays:   {:?}", output.success);
    Ok(())
}

async fn cmd_list_ads(client: &Client, root_id_hex: Option<&str>) -> Result<()> {
    let mut filter = Filter::new().kind(kinds::ADVERTISEMENT);

    if let Some(hex) = root_id_hex {
        let root_id = EventId::from_hex(hex).context("invalid root event id hex")?;
        filter = filter.event(root_id);
    }

    let events = client.fetch_events(filter, Duration::from_secs(10)).await?;

    if events.is_empty() {
        println!("no advertisements found");
        return Ok(());
    }

    println!("found {} advertisement(s):\n", events.len());
    for event in events.iter() {
        let d_tag = event
            .tags
            .iter()
            .find(|t| t.kind() == TagKind::SingleLetter(SingleLetterTag::lowercase(Alphabet::D)))
            .and_then(|t| t.content())
            .unwrap_or("unknown");

        let scheme = event
            .tags
            .iter()
            .find(|t| t.kind() == TagKind::custom("scheme"))
            .and_then(|t| t.content())
            .unwrap_or("unknown");

        let slots = event
            .tags
            .iter()
            .find(|t| t.kind() == TagKind::custom("slots"))
            .and_then(|t| t.content())
            .unwrap_or("?/?");

        println!("  id:     {}", event.id);
        println!("  name:   {d_tag}");
        println!("  scheme: {scheme}");
        println!("  slots:  {slots}");
        println!("  author: {}", event.pubkey);
        println!("  date:   {}", event.created_at);
        println!();
    }

    Ok(())
}

fn load_keys(key_file: &PathBuf) -> Result<Keys> {
    let content = std::fs::read_to_string(key_file)
        .with_context(|| format!("reading key file at {}", key_file.display()))?;
    let trimmed = content.trim();
    let secret = if trimmed.starts_with("nsec") {
        SecretKey::from_bech32(trimmed)?
    } else {
        SecretKey::from_hex(trimmed)?
    };
    Ok(Keys::new(secret))
}

async fn connect(relays_csv: &str, keys: &Keys) -> Result<Client> {
    let client = Client::new(keys.clone());
    for relay in relays_csv.split(',') {
        let relay = relay.trim();
        if !relay.is_empty() {
            client.add_relay(relay).await?;
        }
    }
    client.connect().await;
    Ok(client)
}
