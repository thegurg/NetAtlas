//! Terminal user interface.
//!
//! Presentation layer over application services. No discovery, protocol,
//! database, or fingerprinting business logic lives here.

mod app;
mod event;
mod ui;

use std::time::Duration;

use anyhow::Result;
use crossterm::event::{self as crossterm_event, Event as CrosstermEvent};
use ratatui::DefaultTerminal;
use tokio::sync::mpsc;

use crate::config::Config;

use self::app::App;
use self::event::AppEvent;

const TICK_RATE: Duration = Duration::from_millis(250);

/// Run the interactive TUI.
pub async fn run(config: &Config) -> Result<()> {
    let terminal = ratatui::init();
    let result = run_app(terminal, config).await;
    ratatui::restore();
    result
}

async fn run_app(mut terminal: DefaultTerminal, config: &Config) -> Result<()> {
    let (tx, mut rx) = mpsc::unbounded_channel::<AppEvent>();
    let mut app = App::new(config.clone(), tx.clone())?;
    app.start_initial_load();

    // Input/tick loop in a background thread so rendering stays responsive.
    let input_tx = tx.clone();
    std::thread::spawn(move || input_loop(input_tx));

    loop {
        terminal.draw(|frame| ui::draw(frame, &app))?;

        if app.should_quit {
            break;
        }

        match rx.recv().await {
            Some(event) => app.handle_event(event),
            None => break,
        }
    }

    Ok(())
}

fn input_loop(tx: mpsc::UnboundedSender<AppEvent>) {
    loop {
        if crossterm_event::poll(TICK_RATE).unwrap_or(false) {
            match crossterm_event::read() {
                Ok(CrosstermEvent::Key(key)) => {
                    if tx.send(AppEvent::Input(key)).is_err() {
                        break;
                    }
                }
                Ok(CrosstermEvent::Resize(_, _)) => {
                    if tx.send(AppEvent::Tick).is_err() {
                        break;
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        } else if tx.send(AppEvent::Tick).is_err() {
            break;
        }
    }
}
