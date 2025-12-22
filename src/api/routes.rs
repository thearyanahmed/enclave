use actix_web::web;

mod handlers;

/// Configures all authentication routes for the application.
///
/// # Example
/// ```ignore
/// use actix_web::App;
/// use enclave::api::configure;
///
/// App::new().configure(configure);
/// ```
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(
        web::scope("/auth")
            .route("/register", web::post().to(handlers::register))
            .route("/login", web::post().to(handlers::login))
    );
}
