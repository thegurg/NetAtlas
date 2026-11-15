//! TUI rendering.

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, List, ListItem, Paragraph, Row, Table, Tabs, Wrap};

use crate::domain::InferenceStatus;

use super::app::{App, InputMode, View};

pub fn draw(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(3),
        ])
        .split(frame.area());

    draw_tabs(frame, app, chunks[0]);
    match app.view {
        View::Dashboard => draw_dashboard(frame, app, chunks[1]),
        View::Devices => draw_devices(frame, app, chunks[1]),
        View::DeviceDetail => draw_device_detail(frame, app, chunks[1]),
        View::Map => draw_map(frame, app, chunks[1]),
        View::Dns => draw_dns(frame, app, chunks[1]),
        View::Routes => draw_routes(frame, app, chunks[1]),
        View::Monitoring => draw_monitoring(frame, app, chunks[1]),
        View::History => draw_history(frame, app, chunks[1]),
    }
    draw_status(frame, app, chunks[2]);
}

fn draw_tabs(frame: &mut Frame, app: &App, area: Rect) {
    let titles: Vec<Line> = View::all().iter().map(|v| Line::from(v.title())).collect();
    let selected = View::all().iter().position(|v| *v == app.view).unwrap_or(0);
    let tabs = Tabs::new(titles)
        .block(Block::default().borders(Borders::ALL).title("NetAtlas"))
        .select(selected)
        .highlight_style(Style::default().add_modifier(Modifier::BOLD | Modifier::REVERSED));
    frame.render_widget(tabs, area);
}

fn draw_status(frame: &mut Frame, app: &App, area: Rect) {
    let help = match app.input_mode {
        InputMode::Filter => {
            "Type to filter devices | Enter/Esc: apply & exit filter | Backspace: delete"
        }
        InputMode::Normal => {
            "q quit | r refresh | Tab/1-8 views | / filter | s stale-only | ↑↓/jk/Pg select/scroll | Enter detail | Esc back"
        }
    };
    let status_line = if app.input_mode == InputMode::Filter {
        format!("Filter: {}▌", app.device_filter)
    } else {
        app.status.clone()
    };
    let text = vec![
        Line::from(status_line),
        Line::from(Span::styled(
            help,
            Style::default().add_modifier(Modifier::DIM),
        )),
    ];
    let p = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL).title("Status"))
        .wrap(Wrap { trim: true });
    frame.render_widget(p, area);
}

fn draw_dashboard(frame: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area);

    let stale = app
        .devices_all
        .iter()
        .filter(|d| d.freshness.is_stale())
        .count();
    let summary = vec![
        Line::from(format!("Devices (all): {}", app.devices_all.len())),
        Line::from(format!("Devices (shown): {}", app.devices.len())),
        Line::from(format!("Stale devices: {stale}")),
        Line::from(format!("Scan sessions: {}", app.sessions_count)),
        Line::from(format!("Interfaces: {}", app.interface_count)),
        Line::from(format!(
            "Default gateway: {}",
            app.default_gateway.as_deref().unwrap_or("unknown")
        )),
        Line::from(format!(
            "DNS measurements (recent): {}",
            app.dns_measurements.len()
        )),
        Line::from(format!("Route runs (recent): {}", app.route_runs.len())),
        Line::from(format!("Monitor runs (recent): {}", app.monitor_runs.len())),
        Line::from(format!(
            "Network events (recent): {}",
            app.network_events.len()
        )),
        Line::from(""),
        Line::from(format!(
            "Device filter: '{}'{}",
            app.device_filter,
            if app.stale_only { " (stale only)" } else { "" }
        )),
        Line::from(
            "Data is read from local DB/services. Stale is not 'offline'; unknown is valid.",
        ),
    ];
    let left = Paragraph::new(summary)
        .block(Block::default().borders(Borders::ALL).title("Overview"))
        .wrap(Wrap { trim: true });
    frame.render_widget(left, cols[0]);

    let recent: Vec<ListItem> =
        app.devices
            .iter()
            .take(20)
            .map(|d| {
                let ip = d.ips.first().cloned().unwrap_or_else(|| "-".to_string());
                let name =
                    d.hostnames.first().cloned().unwrap_or_else(|| {
                        d.label.clone().unwrap_or_else(|| "unnamed".to_string())
                    });
                ListItem::new(format!("{ip}  {name}  [{}]", freshness_label(d)))
            })
            .collect();
    let right = List::new(if recent.is_empty() {
        vec![ListItem::new(
            "No devices match current filter/data. Run `netatlas discover` or press r.",
        )]
    } else {
        recent
    })
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Devices (filtered)"),
    );
    frame.render_widget(right, cols[1]);
}

fn draw_devices(frame: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec![
        "IP",
        "Hostname",
        "MAC",
        "Manufacturer",
        "OS",
        "Freshness",
    ])
    .style(Style::default().add_modifier(Modifier::BOLD));

    let visible_height = area.height.saturating_sub(4) as usize; // borders+header
    let start = if app.devices.is_empty() {
        0
    } else {
        app.selected_device
            .saturating_sub(visible_height.saturating_sub(1))
            .min(app.devices.len().saturating_sub(1))
    };
    let end = (start + visible_height.max(1)).min(app.devices.len());

    let rows: Vec<Row> = app.devices[start..end]
        .iter()
        .enumerate()
        .map(|(offset, d)| {
            let i = start + offset;
            let mut row = Row::new(vec![
                Cell::from(d.ips.first().cloned().unwrap_or_else(|| "-".into())),
                Cell::from(
                    d.hostnames
                        .first()
                        .cloned()
                        .unwrap_or_else(|| d.label.clone().unwrap_or_else(|| "-".into())),
                ),
                Cell::from(d.macs.first().cloned().unwrap_or_else(|| "-".into())),
                Cell::from(inference_text(&d.manufacturer.value, d.manufacturer.status)),
                Cell::from(inference_text(&d.os.value, d.os.status)),
                Cell::from(freshness_label(d)),
            ]);
            if i == app.selected_device {
                row = row.style(Style::default().add_modifier(Modifier::REVERSED));
            }
            row
        })
        .collect();

    let title = format!(
        "Devices {}/{} (Enter detail, / filter, s stale-only)",
        if app.devices.is_empty() {
            0
        } else {
            app.selected_device + 1
        },
        app.devices.len()
    );
    let table = if rows.is_empty() {
        Table::new(
            vec![Row::new(vec![
                Cell::from("No devices. Run `netatlas discover` then press r."),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
            ])],
            [
                Constraint::Length(16),
                Constraint::Percentage(25),
                Constraint::Length(18),
                Constraint::Percentage(20),
                Constraint::Percentage(15),
                Constraint::Length(12),
            ],
        )
    } else {
        Table::new(
            rows,
            [
                Constraint::Length(16),
                Constraint::Percentage(25),
                Constraint::Length(18),
                Constraint::Percentage(20),
                Constraint::Percentage(15),
                Constraint::Length(12),
            ],
        )
    }
    .header(header)
    .block(Block::default().borders(Borders::ALL).title(title));
    frame.render_widget(table, area);
}

fn draw_device_detail(frame: &mut Frame, app: &App, area: Rect) {
    let Some(summary) = app.selected_device_summary() else {
        let p = Paragraph::new("No device selected.").block(
            Block::default()
                .borders(Borders::ALL)
                .title("Device Detail"),
        );
        frame.render_widget(p, area);
        return;
    };

    let mut lines = Vec::new();
    lines.push(Line::from(format!("ID: {}", summary.id)));
    lines.push(Line::from(format!(
        "Label: {}",
        summary.label.as_deref().unwrap_or("-")
    )));
    lines.push(Line::from(format!(
        "IPs: {}",
        if summary.ips.is_empty() {
            "-".to_string()
        } else {
            summary.ips.join(", ")
        }
    )));
    lines.push(Line::from(format!(
        "MACs: {}",
        if summary.macs.is_empty() {
            "-".to_string()
        } else {
            summary.macs.join(", ")
        }
    )));
    lines.push(Line::from(format!(
        "Hostnames: {}",
        if summary.hostnames.is_empty() {
            "-".to_string()
        } else {
            summary.hostnames.join(", ")
        }
    )));
    lines.push(Line::from(format!(
        "Freshness: {} (not an offline determination)",
        freshness_label(summary)
    )));
    lines.push(Line::from(""));
    lines.push(Line::from("Inferences (evidence-based):"));
    push_inference(&mut lines, "Manufacturer", &summary.manufacturer);
    push_inference(&mut lines, "Category", &summary.category);
    push_inference(&mut lines, "OS", &summary.os);
    push_inference(&mut lines, "Model", &summary.model);

    if let Some(detail) = &app.device_detail {
        lines.push(Line::from(""));
        lines.push(Line::from(format!(
            "Identifiers: {}",
            detail.identifiers.len()
        )));
        for id in detail.identifiers.iter() {
            lines.push(Line::from(format!(
                "  - {} = {} ({}, {})",
                id.kind.as_str(),
                id.value,
                id.source.as_str(),
                id.confidence.as_str()
            )));
        }
        lines.push(Line::from(""));
        lines.push(Line::from(format!(
            "Evidence: {}  Observations: {}  Services: {}",
            detail.evidence.len(),
            detail.observations.len(),
            detail.services.len()
        )));
        for ev in detail.evidence.iter() {
            lines.push(Line::from(format!(
                "  [evidence] {} = {} (source {}, conf {})",
                ev.property.as_str(),
                value_brief(&ev.candidate),
                ev.source.as_str(),
                ev.confidence.as_str()
            )));
        }
        if !detail.services.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::from("Services:"));
            for svc in &detail.services {
                lines.push(Line::from(format!(
                    "  - {}/{} proto={} product={} version={}",
                    svc.port,
                    svc.transport.as_str(),
                    svc.protocol.as_deref().unwrap_or("-"),
                    svc.product.as_deref().unwrap_or("-"),
                    svc.version.as_deref().unwrap_or("-"),
                )));
            }
        }
    } else {
        lines.push(Line::from(""));
        lines.push(Line::from("Loading detail… (press r to refresh)"));
    }

    let p = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Device Detail (Esc back, ↑↓ scroll)"),
        )
        .wrap(Wrap { trim: false })
        .scroll((app.scroll, 0));
    frame.render_widget(p, area);
}

fn draw_map(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines = Vec::new();
    if let Some(map) = &app.segment_map {
        lines.push(Line::from(map.note.clone()));
        lines.push(Line::from(""));
        if map.segments.is_empty() {
            lines.push(Line::from("No known segments recorded yet."));
        }
        for seg in &map.segments {
            lines.push(Line::from(format!(
                "Segment: {} on {} (gateway: {}, devices: {}, freshness: {})",
                seg.prefix,
                seg.interface,
                seg.gateway
                    .map(|g| g.to_string())
                    .unwrap_or_else(|| "-".into()),
                seg.devices.len(),
                if seg.freshness.is_stale() {
                    "stale"
                } else {
                    "fresh"
                }
            )));
            for d in seg.devices.iter().take(50) {
                let ip = d.ips.first().cloned().unwrap_or_else(|| "-".into());
                let name = d
                    .hostnames
                    .first()
                    .cloned()
                    .unwrap_or_else(|| d.label.clone().unwrap_or_else(|| "unnamed".into()));
                lines.push(Line::from(format!(
                    "  - {ip}  {name}  [{}]",
                    freshness_label(d)
                )));
            }
            if seg.devices.len() > 50 {
                lines.push(Line::from(format!("  … {} more", seg.devices.len() - 50)));
            }
            lines.push(Line::from(""));
        }
        if !map.unassigned.is_empty() {
            lines.push(Line::from(format!(
                "Unassigned devices: {}",
                map.unassigned.len()
            )));
            for d in map.unassigned.iter().take(30) {
                let ip = d.ips.first().cloned().unwrap_or_else(|| "-".into());
                let name = d.label.clone().unwrap_or_else(|| "unnamed".into());
                lines.push(Line::from(format!("  - {ip}  {name}")));
            }
        }
    } else {
        lines.push(Line::from("Loading map… (press r to refresh)"));
    }
    let p = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Map (logical segment view, ↑↓ scroll)"),
        )
        .wrap(Wrap { trim: false })
        .scroll((app.scroll, 0));
    frame.render_widget(p, area);
}

fn draw_dns(frame: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec!["Time", "Name", "Type", "Resolver", "Outcome", "ms"])
        .style(Style::default().add_modifier(Modifier::BOLD));
    let rows: Vec<Row> = app
        .dns_measurements
        .iter()
        .take(200)
        .map(|m| {
            Row::new(vec![
                Cell::from(crate::domain::time::format_short(m.queried_at_ms)),
                Cell::from(m.query.name.clone()),
                Cell::from(m.query.record_type.as_str().to_string()),
                Cell::from(m.resolver.label.clone()),
                Cell::from(m.outcome.as_str().to_string()),
                Cell::from(m.elapsed_ms.to_string()),
            ])
        })
        .collect();
    let table = if rows.is_empty() {
        Table::new(
            vec![Row::new(vec![
                Cell::from("No DNS measurements yet. Use `netatlas dns query ...` then refresh."),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
            ])],
            [
                Constraint::Length(20),
                Constraint::Percentage(30),
                Constraint::Length(8),
                Constraint::Percentage(20),
                Constraint::Length(12),
                Constraint::Length(8),
            ],
        )
    } else {
        Table::new(
            rows,
            [
                Constraint::Length(20),
                Constraint::Percentage(30),
                Constraint::Length(8),
                Constraint::Percentage(20),
                Constraint::Length(12),
                Constraint::Length(8),
            ],
        )
    }
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("DNS History (recent)"),
    );
    frame.render_widget(table, area);
}

fn draw_routes(frame: &mut Frame, app: &App, area: Rect) {
    let header = Row::new(vec![
        "Time", "Target", "Method", "Status", "Reached", "Hops", "Samples",
    ])
    .style(Style::default().add_modifier(Modifier::BOLD));
    let rows: Vec<Row> = app
        .route_runs
        .iter()
        .take(200)
        .map(|r| {
            Row::new(vec![
                Cell::from(crate::domain::time::format_short(r.started_at_ms)),
                Cell::from(format!("{} ({})", r.target, r.target_ip)),
                Cell::from(r.method.as_str().to_string()),
                Cell::from(r.status.as_str().to_string()),
                Cell::from(if r.target_reached { "yes" } else { "no" }.to_string()),
                Cell::from(r.hops.len().to_string()),
                Cell::from(r.sample_count().to_string()),
            ])
        })
        .collect();
    let table = if rows.is_empty() {
        Table::new(
            vec![Row::new(vec![
                Cell::from("No route runs yet. Use `netatlas route trace ...` then refresh."),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
            ])],
            [
                Constraint::Length(20),
                Constraint::Percentage(35),
                Constraint::Length(8),
                Constraint::Length(12),
                Constraint::Length(8),
                Constraint::Length(6),
                Constraint::Length(8),
            ],
        )
    } else {
        Table::new(
            rows,
            [
                Constraint::Length(20),
                Constraint::Percentage(35),
                Constraint::Length(8),
                Constraint::Length(12),
                Constraint::Length(8),
                Constraint::Length(6),
                Constraint::Length(8),
            ],
        )
    }
    .header(header)
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Route History (recent) — timeouts are measurements, not proof of broken route"),
    );
    frame.render_widget(table, area);
}

fn draw_monitoring(frame: &mut Frame, app: &App, area: Rect) {
    let rows_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(45), Constraint::Percentage(55)])
        .split(area);

    let run_rows: Vec<Row> = app
        .monitor_runs
        .iter()
        .take(100)
        .map(|r| {
            Row::new(vec![
                Cell::from(crate::domain::time::format_short(r.started_at_ms)),
                Cell::from(r.kind.clone()),
                Cell::from(r.status.clone()),
                Cell::from(r.target.clone().unwrap_or_else(|| "-".into())),
                Cell::from(r.error.clone().unwrap_or_else(|| "-".into())),
            ])
        })
        .collect();
    let runs_table = if run_rows.is_empty() {
        Table::new(
            vec![Row::new(vec![
                Cell::from("No monitor runs yet. Use `netatlas monitor scan ...` then refresh."),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
            ])],
            [
                Constraint::Length(20),
                Constraint::Length(10),
                Constraint::Length(12),
                Constraint::Percentage(30),
                Constraint::Percentage(40),
            ],
        )
    } else {
        Table::new(
            run_rows,
            [
                Constraint::Length(20),
                Constraint::Length(10),
                Constraint::Length(12),
                Constraint::Percentage(30),
                Constraint::Percentage(40),
            ],
        )
    }
    .header(
        Row::new(vec!["Started", "Kind", "Status", "Target", "Error"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Monitor Runs (recent)"),
    );
    frame.render_widget(runs_table, rows_layout[0]);

    let ev_rows: Vec<Row> = app
        .network_events
        .iter()
        .take(200)
        .map(|e| {
            Row::new(vec![
                Cell::from(crate::domain::time::format_short(e.observed_at_ms)),
                Cell::from(e.severity.clone()),
                Cell::from(e.kind.clone()),
                Cell::from(e.subject_type.clone().unwrap_or_else(|| "-".into())),
                Cell::from(e.message.clone()),
            ])
        })
        .collect();
    let events_table = if ev_rows.is_empty() {
        Table::new(
            vec![Row::new(vec![
                Cell::from("No network events recorded."),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
            ])],
            [
                Constraint::Length(20),
                Constraint::Length(10),
                Constraint::Length(16),
                Constraint::Length(12),
                Constraint::Percentage(50),
            ],
        )
    } else {
        Table::new(
            ev_rows,
            [
                Constraint::Length(20),
                Constraint::Length(10),
                Constraint::Length(16),
                Constraint::Length(12),
                Constraint::Percentage(50),
            ],
        )
    }
    .header(
        Row::new(vec!["Observed", "Severity", "Kind", "Subject", "Message"])
            .style(Style::default().add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title("Network Events (recent) — change/not-observed are evidence-based"),
    );
    frame.render_widget(events_table, rows_layout[1]);
}

fn draw_history(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines = Vec::new();
    if let Some(report) = &app.change_report {
        lines.push(Line::from(format!(
            "Current session: {} ({})",
            report.current.id,
            report.current.status.as_str()
        )));
        if let Some(prev) = &report.previous {
            lines.push(Line::from(format!(
                "Previous session: {} ({})",
                prev.id,
                prev.status.as_str()
            )));
        } else {
            lines.push(Line::from("Previous session: none".to_string()));
        }
        lines.push(Line::from(format!("Comparable: {}", report.comparable)));
        if let Some(note) = &report.note {
            lines.push(Line::from(""));
            lines.push(Line::from(format!("Note: {note}")));
        }
        lines.push(Line::from(""));
        if report.events.is_empty() {
            lines.push(Line::from(
                "No change events derived (or comparison unavailable).",
            ));
        } else {
            lines.push(Line::from(format!("Events: {}", report.events.len())));
            for ev in &report.events {
                lines.push(Line::from(format!(
                    "  - [{}] device {}: {}",
                    ev.kind.as_str(),
                    ev.device_id,
                    ev.summary
                )));
            }
        }
    } else {
        lines.push(Line::from("Loading history/changes… (press r to refresh)"));
    }
    let p = Paragraph::new(lines)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("History / Changes (latest comparable sessions, ↑↓ scroll)"),
        )
        .wrap(Wrap { trim: false })
        .scroll((app.scroll, 0));
    frame.render_widget(p, area);
}

fn freshness_label(d: &crate::domain::DeviceSummary) -> &'static str {
    if d.freshness.is_stale() {
        "stale"
    } else {
        "fresh"
    }
}

fn inference_text(value: &Option<serde_json::Value>, status: InferenceStatus) -> String {
    match value {
        Some(v) => match v {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        },
        None => format!("Unknown ({})", status.as_str()),
    }
}

fn push_inference(lines: &mut Vec<Line<'_>>, label: &str, view: &crate::domain::InferenceView) {
    let val = inference_text(&view.value, view.status);
    lines.push(Line::from(format!(
        "  {label}: {val} [confidence: {}, status: {}]",
        view.confidence.as_str(),
        view.status.as_str()
    )));
    if let Some(reason) = view.unknown_reason {
        lines.push(Line::from(format!("    reason: {}", reason.as_str())));
    }
}

fn value_brief(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        other => {
            let s = other.to_string();
            if s.len() > 80 {
                format!("{}…", &s[..80])
            } else {
                s
            }
        }
    }
}
