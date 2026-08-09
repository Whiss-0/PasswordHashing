using Microsoft.AspNetCore.Mvc;
using Api.Modules.AuthorizationModule;

namespace Api.HTTP
{
    /// <summary>
    /// Translates a <see cref="ServiceResult"/> into an HTTP response:
    ///   • Applies all cookie instructions (pending, auth tokens, device ID, clears).
    ///   • Builds the correct JSON body.
    ///   • Returns the appropriate <see cref="IActionResult"/> status code.
    /// </summary>
    public interface IHttpResponse
    {
        IActionResult ApplyAndRespond(ServiceResult result);
    }
}
