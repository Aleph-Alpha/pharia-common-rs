#[cfg(feature = "opentelemetry")]
use opentelemetry::trace::TraceContextExt;
use reqwest_middleware::RequestBuilder;
#[cfg(feature = "opentelemetry")]
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// Extension trait for `RequestBuilder` to extract open telemetry trace id and state from tracing
/// context and inject them into outgoing requests as OpenTelemetry headers.
pub trait RequestBuilderExt {
    fn with_opentelemery_headers(self) -> Self;
}

impl RequestBuilderExt for RequestBuilder {
    /// Compiling without opentelemetry means we just do nothing.
    #[cfg(not(feature = "opentelemetry"))]
    fn with_opentelemery_headers(self) -> Self {
        self
    }

    #[cfg(feature = "opentelemetry")]
    fn with_opentelemery_headers(self) -> Self {
        // Generic tracing Span
        let span = tracing::Span::current();

        // OpenTelemetry specific context of span
        let otel_context = span.context();
        let otel_span = otel_context.span();
        let otel_span_context = otel_span.span_context();

        // Is the current span sampled?
        //
        // The open telemetry span context holds information whether the current span is sampled.
        // By respecting the parent's span decision for sampling, we allow remote services to decide
        // whether a span is sampled or not. If no information is provided, our probability-based
        // sampler will decide whether to sample the span or not.
        let is_sampled = otel_span_context.is_sampled();
        self
    }
}
