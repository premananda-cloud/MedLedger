// src/components/ErrorBoundary.jsx
import { Component } from "react";

export class ErrorBoundary extends Component {
  state = { hasError: false, error: null };

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="auth-root">
          <div className="auth-card">
            <h2>Something went wrong</h2>
            <p>{this.state.error?.message}</p>
            <button onClick={() => window.location.reload()}>Reload app</button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
