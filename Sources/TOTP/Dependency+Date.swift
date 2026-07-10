//
//  Dependency+Date.swift
//  swift-one-time-password
//
//  Created by Coen ten Thije Boonkkamp on 2026-07-10.
//

import Dependencies
import Foundation

// MARK: - Date Dependency Key

/// Dependency key providing the current wall-clock date.
///
/// Resolution chain:
/// - **Live**: `Date()` — real wall-clock time
/// - **Preview**/**Test**: defaults to `liveValue`; override explicitly for
///   deterministic time:
///
/// ```swift
/// @Test(.dependency(\.date, .constant(Date(timeIntervalSince1970: 0))))
/// func timedFeature() { ... }
/// ```
private enum DateKey: Dependency.Key {}

extension DateKey {
  static var liveValue: Date.Generator {
    Date.Generator { Date() }
  }
}

// MARK: - Dependency.Values Extension

extension __DependencyValues {
  /// A controllable source of the current date.
  ///
  /// In production, resolves to the real wall-clock `Date()`.
  ///
  /// ## Usage
  ///
  /// ```swift
  /// @Dependency(\.date) var date
  /// let now = date()
  /// ```
  ///
  /// ## Test Override
  ///
  /// ```swift
  /// withDependencies {
  ///     $0.date = .constant(Date(timeIntervalSince1970: 1_234_567_890))
  /// } operation: {
  ///     // date() resolves to the fixed instant
  /// }
  /// ```
  public var date: Date.Generator {
    get { self[DateKey.self] }
    set { self[DateKey.self] = newValue }
  }
}
