use anyhow::Result;
use axum::http::HeaderMap;
use axum::response::{Html, IntoResponse};
use axum::{
    extract::{Path, State},
    http::StatusCode,
    routing::get,
    Router,
};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};
use tower_http::services::ServeDir;
use tracing::{info, warn};

#[derive(Debug)]
struct HttpServeState {
    path: PathBuf,
}

pub async fn process_http_serve(path: PathBuf, port: u16) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Serving {:?} on {}", path, addr);

    let state = HttpServeState { path: path.clone() };
    // axum router
    let router = Router::new()
        .nest_service("/tower", ServeDir::new(path))
        .route("/", get(root_directory_handler))
        .route("/*path", get(file_handler))
        .with_state(Arc::new(state));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

async fn file_handler(
    State(state): State<Arc<HttpServeState>>,
    Path(path): Path<String>,
) -> (StatusCode, HeaderMap, String) {
    info!("path = {path}");
    let path = PathBuf::from(path);
    let entry_to_read = std::path::Path::new(&state.path).join(&path);
    info!("Reading file {:?}", entry_to_read);
    if !entry_to_read.exists() {
        (
            StatusCode::NOT_FOUND,
            Default::default(),
            format!("File {} note found", entry_to_read.display()),
        )
    } else if entry_to_read.is_dir() {
        match tokio::fs::read_dir(&entry_to_read).await {
            Ok(mut read_dir) => {
                let mut html = match path.parent() {
                    Some(parent) => {
                        format!(
                            "<p>{}</p><a href=\"/{}\">👆</a><ul>",
                            path.display(),
                            parent.display()
                        )
                    }
                    None => format!("<p>{}</p><ul>", path.display()),
                };
                while let Some(entry) = read_dir.next_entry().await.transpose() {
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(e) => {
                            return (
                                StatusCode::INTERNAL_SERVER_ERROR,
                                Default::default(),
                                e.to_string(),
                            );
                        }
                    };
                    let full_path = entry.path();
                    let label = full_path
                        .strip_prefix(&entry_to_read)
                        .expect("impossible")
                        .display()
                        .to_string();
                    let href = full_path
                        .strip_prefix(&state.path)
                        .expect("impossible")
                        .display()
                        .to_string();
                    info!("href: {}, label: {}", href, label);
                    html += "<li><a href=\"/";
                    html += &href;
                    html += "\">";
                    html += &label;
                    html += "</a></li>";
                }

                html.push_str("</ul>");
                let mut headers = HeaderMap::default();
                headers.append(
                    axum::http::header::CONTENT_TYPE,
                    axum::http::header::HeaderValue::from_static("text/html; charset=UTF-8"),
                );
                (StatusCode::OK, headers, html)
            }
            Err(e) => {
                warn!("Error reading directory: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Default::default(),
                    e.to_string(),
                )
            }
        }
    } else if entry_to_read.is_file() {
        match tokio::fs::read_to_string(entry_to_read).await {
            Ok(content) => {
                info!("Read {} bytes", content.len());
                (StatusCode::OK, Default::default(), content)
            }
            Err(e) => {
                warn!("Error reading file: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Default::default(),
                    e.to_string(),
                )
            }
        }
    } else {
        (
            StatusCode::BAD_REQUEST,
            Default::default(),
            "Invalid file type".into(),
        )
    }
}

async fn root_directory_handler(State(state): State<Arc<HttpServeState>>) -> impl IntoResponse {
    if state.path.is_dir() {
        match tokio::fs::read_dir(&state.path).await {
            Ok(mut read_dir) => {
                let mut html = String::from("<p></p><ul>");
                while let Some(entry) = read_dir.next_entry().await.transpose() {
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(e) => {
                            return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
                                .into_response()
                        }
                    };
                    let full_path = entry.path();
                    let href = full_path
                        .strip_prefix(&state.path)
                        .expect("impossible")
                        .display()
                        .to_string();
                    html += "<li><a href=\"/";
                    html += &href;
                    html += "\">";
                    html += &href;
                    html += "</a></li>";
                }

                html.push_str("</ul>");
                (StatusCode::OK, Html(html)).into_response()
            }
            Err(e) => {
                warn!("Error reading directory: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
            }
        }
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Directory doesn't exists",
        )
            .into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_file_handler() {
        let state = Arc::new(HttpServeState {
            path: PathBuf::from("."),
        });
        let (status, _, content) = file_handler(State(state), Path("Cargo.toml".to_string())).await;
        assert_eq!(status, StatusCode::OK);
        assert!(content.trim().starts_with("[package]"));
    }
}
