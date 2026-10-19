import { Component, Suspense } from "react";
import { useLocation } from "react-router-dom";
import { Notice, PageLoading } from "./Shared.jsx";

export class PageErrorBoundary extends Component {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  componentDidUpdate(previous) {
    if (this.state.failed && previous.resetKey !== this.props.resetKey) {
      this.setState({ failed: false });
    }
  }

  render() {
    if (this.state.failed) {
      return <main className="content">
        <Notice type="error">This page could not be loaded. Reload the page to retry.</Notice>
        <button className="btn btn-primary" onClick={() => window.location.reload()}>Reload page</button>
      </main>;
    }
    return this.props.children;
  }
}

export default function LazyBoundary({ children, label }) {
  const { pathname } = useLocation();
  return <PageErrorBoundary resetKey={pathname}>
    <Suspense fallback={<PageLoading label={label} />}>{children}</Suspense>
  </PageErrorBoundary>;
}
