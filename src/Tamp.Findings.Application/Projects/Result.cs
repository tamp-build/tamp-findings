namespace Tamp.Findings.Application.Projects;

/// <summary>
/// The outcome of a command, distinguishing "you may not" from "that does not
/// work".
///
/// They read differently to the user and belong in different places: a denial
/// is a disabled control with a reason, an invalid input is a message beside
/// the field. Collapsing them into one bool loses that.
/// </summary>
public sealed record Result<T>(bool Success, T? Value, string? Error, bool WasDenied)
{
    public static Result<T> Ok(T value) => new(true, value, null, false);
    public static Result<T> Denied(string reason) => new(false, default, reason, true);
    public static Result<T> Invalid(string message) => new(false, default, message, false);
}
