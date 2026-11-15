//! TUI events.

use crossterm::event::KeyEvent;

use crate::application::inventory::{ChangeReport, SegmentMap};
use crate::application::model::SessionRecord;
use crate::domain::NetworkContext;
use crate::domain::{DeviceDetail, DeviceSummary, DnsMeasurement, RouteRun};
use crate::infrastructure::storage::{MonitorRunRow, NetworkEventRow};

#[derive(Debug)]
pub enum AppEvent {
    Input(KeyEvent),
    Tick,
    DevicesLoaded(Result<Vec<DeviceSummary>, String>),
    DeviceDetailLoaded(Box<Result<Option<DeviceDetail>, String>>),
    SessionsLoaded(Result<Vec<SessionRecord>, String>),
    NetworkContextLoaded(Result<NetworkContext, String>),
    DnsHistoryLoaded(Result<Vec<DnsMeasurement>, String>),
    RouteHistoryLoaded(Result<Vec<RouteRun>, String>),
    MonitorRunsLoaded(Result<Vec<MonitorRunRow>, String>),
    NetworkEventsLoaded(Result<Vec<NetworkEventRow>, String>),
    MapLoaded(Box<Result<SegmentMap, String>>),
    ChangesLoaded(Box<Result<Option<ChangeReport>, String>>),
}
