//! TUI application state and actions.

use std::collections::HashMap;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::application::inventory::{self, ChangeReport, DeviceFilter, SegmentMap};
use crate::application::{dns, route};
use crate::config::Config;
use crate::domain::time::now_ms;
use crate::domain::{DeviceDetail, DeviceSummary, DnsMeasurement, RouteRun};
use crate::infrastructure::storage::{MonitorRunRow, NetworkEventRow};
use crate::infrastructure::{netlink, storage::Store};

use super::event::AppEvent;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum View {
    Dashboard,
    Devices,
    DeviceDetail,
    Map,
    Dns,
    Routes,
    Monitoring,
    History,
}

impl View {
    pub fn title(self) -> &'static str {
        match self {
            Self::Dashboard => "Dashboard",
            Self::Devices => "Devices",
            Self::DeviceDetail => "Device Detail",
            Self::Map => "Map",
            Self::Dns => "DNS",
            Self::Routes => "Routes",
            Self::Monitoring => "Monitoring",
            Self::History => "History/Changes",
        }
    }

    pub fn all() -> [View; 8] {
        [
            Self::Dashboard,
            Self::Devices,
            Self::DeviceDetail,
            Self::Map,
            Self::Dns,
            Self::Routes,
            Self::Monitoring,
            Self::History,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    Normal,
    Filter,
}

pub struct App {
    pub config: Config,
    pub tx: mpsc::UnboundedSender<AppEvent>,
    pub should_quit: bool,
    pub view: View,
    pub input_mode: InputMode,
    pub status: String,
    pub loading: bool,

    pub devices_all: Vec<DeviceSummary>,
    pub devices: Vec<DeviceSummary>,
    pub selected_device: usize,
    pub device_detail: Option<DeviceDetail>,
    pub device_details_cache: HashMap<Uuid, DeviceDetail>,
    pub device_filter: String,
    pub stale_only: bool,

    pub dns_measurements: Vec<DnsMeasurement>,
    pub route_runs: Vec<RouteRun>,
    pub sessions_count: usize,
    pub interface_count: usize,
    pub default_gateway: Option<String>,

    pub monitor_runs: Vec<MonitorRunRow>,
    pub network_events: Vec<NetworkEventRow>,
    pub segment_map: Option<SegmentMap>,
    pub change_report: Option<ChangeReport>,

    pub scroll: u16,
}

impl App {
    pub fn new(config: Config, tx: mpsc::UnboundedSender<AppEvent>) -> anyhow::Result<Self> {
        Ok(Self {
            config,
            tx,
            should_quit: false,
            view: View::Dashboard,
            input_mode: InputMode::Normal,
            status: "Loading…".to_string(),
            loading: false,
            devices_all: Vec::new(),
            devices: Vec::new(),
            selected_device: 0,
            device_detail: None,
            device_details_cache: HashMap::new(),
            device_filter: String::new(),
            stale_only: false,
            dns_measurements: Vec::new(),
            route_runs: Vec::new(),
            sessions_count: 0,
            interface_count: 0,
            default_gateway: None,
            monitor_runs: Vec::new(),
            network_events: Vec::new(),
            segment_map: None,
            change_report: None,
            scroll: 0,
        })
    }

    pub fn start_initial_load(&mut self) {
        self.refresh_all();
    }

    pub fn refresh_all(&mut self) {
        self.loading = true;
        self.status = "Refreshing…".to_string();
        self.load_devices();
        self.load_network_context();
        self.load_dns();
        self.load_routes();
        self.load_sessions_count();
        self.load_monitoring();
        self.load_map();
        self.load_changes();
    }

    fn spawn<F>(&self, f: F)
    where
        F: FnOnce(mpsc::UnboundedSender<AppEvent>, Config) + Send + 'static,
    {
        let tx = self.tx.clone();
        let config = self.config.clone();
        std::thread::spawn(move || f(tx, config));
    }

    fn load_devices(&self) {
        self.spawn(|tx, config| {
            let result = (|| {
                let store = Store::open(&config.db_path).map_err(|e| e.to_string())?;
                inventory::list_devices(&store, &DeviceFilter::default(), now_ms())
                    .map_err(|e| e.to_string())
            })();
            let _ = tx.send(AppEvent::DevicesLoaded(result));
        });
    }

    fn load_sessions_count(&self) {
        self.spawn(|tx, config| {
            let result = (|| {
                let store = Store::open(&config.db_path).map_err(|e| e.to_string())?;
                store.list_sessions().map_err(|e| e.to_string())
            })();
            let _ = tx.send(AppEvent::SessionsLoaded(result));
        });
    }

    fn load_network_context(&self) {
        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build();
            let result = match rt {
                Ok(rt) => rt
                    .block_on(async { netlink::snapshot().await })
                    .map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            };
            let _ = tx.send(AppEvent::NetworkContextLoaded(result));
        });
    }

    fn load_dns(&self) {
        self.spawn(|tx, config| {
            let result = (|| {
                let store = Store::open(&config.db_path).map_err(|e| e.to_string())?;
                dns::history(
                    &store,
                    &dns::DnsHistoryFilter {
                        limit: 50,
                        ..Default::default()
                    },
                )
                .map_err(|e| e.to_string())
            })();
            let _ = tx.send(AppEvent::DnsHistoryLoaded(result));
        });
    }

    fn load_routes(&self) {
        self.spawn(|tx, config| {
            let result = (|| {
                let store = Store::open(&config.db_path).map_err(|e| e.to_string())?;
                route::history(
                    &store,
                    &route::RouteHistoryFilter {
                        limit: 50,
                        ..Default::default()
                    },
                )
                .map_err(|e| e.to_string())
            })();
            let _ = tx.send(AppEvent::RouteHistoryLoaded(result));
        });
    }

    fn load_monitoring(&self) {
        self.spawn(|tx, config| {
            let runs = (|| {
                let store = Store::open(&config.db_path).map_err(|e| e.to_string())?;
                store.list_monitor_runs(None, 50).map_err(|e| e.to_string())
            })();
            let _ = tx.send(AppEvent::MonitorRunsLoaded(runs));
        });
        self.spawn(|tx, config| {
            let events = (|| {
                let store = Store::open(&config.db_path).map_err(|e| e.to_string())?;
                store
                    .list_network_events(None, None, 100)
                    .map_err(|e| e.to_string())
            })();
            let _ = tx.send(AppEvent::NetworkEventsLoaded(events));
        });
    }

    fn load_map(&self) {
        self.spawn(|tx, config| {
            let result = (|| {
                let store = Store::open(&config.db_path).map_err(|e| e.to_string())?;
                inventory::build_map(&store, None, now_ms()).map_err(|e| e.to_string())
            })();
            let _ = tx.send(AppEvent::MapLoaded(Box::new(result)));
        });
    }

    fn load_changes(&self) {
        self.spawn(|tx, config| {
            let result = (|| {
                let store = Store::open(&config.db_path).map_err(|e| e.to_string())?;
                inventory::changes_for_session(&store, None).map_err(|e| e.to_string())
            })();
            let _ = tx.send(AppEvent::ChangesLoaded(Box::new(result)));
        });
    }

    pub fn load_selected_device_detail(&mut self) {
        let Some(device) = self.devices.get(self.selected_device) else {
            return;
        };
        let id = device.id;
        if let Some(detail) = self.device_details_cache.get(&id) {
            self.device_detail = Some(detail.clone());
            return;
        }
        self.status = format!("Loading device {id}…");
        self.spawn(move |tx, config| {
            let result = (|| {
                let store = Store::open(&config.db_path).map_err(|e| e.to_string())?;
                store.get_device(id).map_err(|e| e.to_string())
            })();
            let _ = tx.send(AppEvent::DeviceDetailLoaded(Box::new(result)));
        });
    }

    fn apply_device_filter(&mut self) {
        let needle = self.device_filter.trim().to_lowercase();
        self.devices = self
            .devices_all
            .iter()
            .filter(|d| {
                if self.stale_only && !d.freshness.is_stale() {
                    return false;
                }
                if needle.is_empty() {
                    return true;
                }
                let mut hay = String::new();
                if let Some(l) = &d.label {
                    hay.push_str(l);
                    hay.push(' ');
                }
                for v in &d.ips {
                    hay.push_str(v);
                    hay.push(' ');
                }
                for v in &d.macs {
                    hay.push_str(v);
                    hay.push(' ');
                }
                for v in &d.hostnames {
                    hay.push_str(v);
                    hay.push(' ');
                }
                hay.push_str(&d.manufacturer.display_value());
                hay.push(' ');
                hay.push_str(&d.os.display_value());
                hay.to_lowercase().contains(&needle)
            })
            .cloned()
            .collect();
        if self.selected_device >= self.devices.len() {
            self.selected_device = self.devices.len().saturating_sub(1);
        }
    }

    pub fn handle_event(&mut self, event: AppEvent) {
        match event {
            AppEvent::Input(key) => self.handle_key(key),
            AppEvent::Tick => {}
            AppEvent::DevicesLoaded(result) => match result {
                Ok(devices) => {
                    self.devices_all = devices;
                    self.apply_device_filter();
                    self.loading = false;
                    self.status = format!("{} device(s)", self.devices.len());
                    if self.view == View::DeviceDetail {
                        self.load_selected_device_detail();
                    }
                }
                Err(error) => {
                    self.loading = false;
                    self.status = format!("Failed to load devices: {error}");
                }
            },
            AppEvent::DeviceDetailLoaded(result) => match *result {
                Ok(Some(detail)) => {
                    self.device_details_cache
                        .insert(detail.summary.id, detail.clone());
                    self.device_detail = Some(detail);
                    self.status = "Device detail loaded".to_string();
                }
                Ok(None) => {
                    self.device_detail = None;
                    self.status = "Device not found".to_string();
                }
                Err(error) => {
                    self.status = format!("Failed to load device detail: {error}");
                }
            },
            AppEvent::SessionsLoaded(result) => {
                if let Ok(sessions) = result {
                    self.sessions_count = sessions.len();
                }
            }
            AppEvent::NetworkContextLoaded(result) => {
                if let Ok(ctx) = result {
                    self.interface_count = ctx.interfaces.len();
                    self.default_gateway = ctx.default_gateway.map(|ip| ip.to_string());
                }
            }
            AppEvent::DnsHistoryLoaded(result) => {
                if let Ok(items) = result {
                    self.dns_measurements = items;
                }
            }
            AppEvent::RouteHistoryLoaded(result) => {
                if let Ok(items) = result {
                    self.route_runs = items;
                }
            }
            AppEvent::MonitorRunsLoaded(result) => {
                if let Ok(items) = result {
                    self.monitor_runs = items;
                }
            }
            AppEvent::NetworkEventsLoaded(result) => {
                if let Ok(items) = result {
                    self.network_events = items;
                }
            }
            AppEvent::MapLoaded(result) => {
                if let Ok(map) = *result {
                    self.segment_map = Some(map);
                }
            }
            AppEvent::ChangesLoaded(result) => {
                if let Ok(report) = *result {
                    self.change_report = report;
                }
            }
        }
    }

    fn handle_key(&mut self, key: KeyEvent) {
        if self.input_mode == InputMode::Filter {
            self.handle_filter_key(key);
            return;
        }

        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.should_quit = true;
            return;
        }
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('r') => self.refresh_all(),
            KeyCode::Tab => self.next_view(),
            KeyCode::BackTab => self.prev_view(),
            KeyCode::Char('1') => self.set_view(View::Dashboard),
            KeyCode::Char('2') => self.set_view(View::Devices),
            KeyCode::Char('3') => self.set_view(View::DeviceDetail),
            KeyCode::Char('4') => self.set_view(View::Map),
            KeyCode::Char('5') => self.set_view(View::Dns),
            KeyCode::Char('6') => self.set_view(View::Routes),
            KeyCode::Char('7') => self.set_view(View::Monitoring),
            KeyCode::Char('8') => self.set_view(View::History),
            KeyCode::Char('/') => {
                self.input_mode = InputMode::Filter;
                self.status =
                    "Filter mode: type to search devices, Enter/Esc to exit, Backspace to delete"
                        .to_string();
            }
            KeyCode::Char('s') => {
                self.stale_only = !self.stale_only;
                self.apply_device_filter();
                self.status = if self.stale_only {
                    "Showing stale devices only".to_string()
                } else {
                    "Showing all devices".to_string()
                };
            }
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::PageDown => self.move_selection(10),
            KeyCode::PageUp => self.move_selection(-10),
            KeyCode::Home => {
                self.selected_device = 0;
                self.scroll = 0;
            }
            KeyCode::End => {
                if !self.devices.is_empty() {
                    self.selected_device = self.devices.len() - 1;
                }
            }
            KeyCode::Enter => {
                if self.view == View::Devices {
                    self.set_view(View::DeviceDetail);
                }
            }
            KeyCode::Esc if self.view == View::DeviceDetail => {
                self.set_view(View::Devices);
            }
            _ => {}
        }
    }

    fn handle_filter_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => {
                self.input_mode = InputMode::Normal;
                self.status = format!(
                    "Filter: '{}'{} ({} device(s))",
                    self.device_filter,
                    if self.stale_only { " [stale]" } else { "" },
                    self.devices.len()
                );
            }
            KeyCode::Backspace => {
                self.device_filter.pop();
                self.apply_device_filter();
            }
            KeyCode::Char(c) => {
                self.device_filter.push(c);
                self.apply_device_filter();
            }
            _ => {}
        }
    }

    fn set_view(&mut self, view: View) {
        self.view = view;
        self.scroll = 0;
        if view == View::DeviceDetail {
            self.load_selected_device_detail();
        }
    }

    fn next_view(&mut self) {
        let views = View::all();
        let idx = views.iter().position(|v| *v == self.view).unwrap_or(0);
        self.set_view(views[(idx + 1) % views.len()]);
    }

    fn prev_view(&mut self) {
        let views = View::all();
        let idx = views.iter().position(|v| *v == self.view).unwrap_or(0);
        self.set_view(views[(idx + views.len() - 1) % views.len()]);
    }

    fn move_selection(&mut self, delta: i32) {
        if matches!(self.view, View::Devices | View::DeviceDetail) && !self.devices.is_empty() {
            let len = self.devices.len() as i32;
            let current = self.selected_device as i32;
            let next = (current + delta).clamp(0, len - 1) as usize;
            self.selected_device = next;
            if self.view == View::DeviceDetail {
                self.load_selected_device_detail();
            }
        } else {
            // Scroll for text-heavy views
            let next = (self.scroll as i32 + delta).max(0) as u16;
            self.scroll = next;
        }
    }

    pub fn selected_device_summary(&self) -> Option<&DeviceSummary> {
        self.devices.get(self.selected_device)
    }
}
