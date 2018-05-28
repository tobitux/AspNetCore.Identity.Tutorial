using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WebApplication1.Models;

namespace WebApplication1.Controllers
{
    public class HomeController : Controller
    {
        private readonly UserManager<PluralsightUser> _userManager;

        private readonly IUserClaimsPrincipalFactory<PluralsightUser>
            _claimsPrincipalFactory;

        private readonly SignInManager<PluralsightUser> _signInManager;

        public HomeController(UserManager<PluralsightUser> userManager,
            IUserClaimsPrincipalFactory<PluralsightUser> claimsPrincipalFactory,
            SignInManager<PluralsightUser> signInManager)
        {
            _userManager = userManager;
            _claimsPrincipalFactory = claimsPrincipalFactory;
            _signInManager = signInManager;
        }

        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public IActionResult About()
        {
            ViewData["Message"] = "Your application description page.";

            return View();
        }

        public IActionResult Contact()
        {
            ViewData["Message"] = "Your contact page.";

            return View();
        }

        public IActionResult Error()
        {
            return View(new ErrorViewModel
            {
                RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier
            });
        }

        [HttpGet]
        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByNameAsync(model.UserName);
                if (user == null)
                {
                    user = new PluralsightUser()
                    {
                        Id = Guid.NewGuid().ToString(),
                        UserName = model.UserName,
                        Email = model.UserName
                    };

                    var result =
                        await _userManager.CreateAsync(user, model.Password);

                    if (result.Succeeded)
                    {
                        var token =
                            await _userManager
                                .GenerateEmailConfirmationTokenAsync(user);

                        var resetUrl = Url.Action("ConfirmEmailAddress", "Home",
                            new { token = token, email = user.Email },
                            Request.Scheme);

                        System.IO.File.WriteAllText("confirmationLink.txt", resetUrl);
                    }
                    else
                    {
                        foreach (var error in result.Errors)
                        {
                            ModelState.AddModelError("", error.Description);
                        }

                        return View();
                    }
                }

                return View("Success");
            }

            return View();
        }

        public async Task<ActionResult> ConfirmEmailAddress(string token,
            string email)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    return View("Success");
                }
            }

            return View("Error");
        }

        [HttpGet]
        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByNameAsync(model.UserName);

                if (user != null && !await _userManager.IsLockedOutAsync(user))
                {
                    if (await _userManager.CheckPasswordAsync(user, model.Password))
                    {
                        if (!await _userManager.IsEmailConfirmedAsync(user))
                        {
                            ModelState.AddModelError("", "Email not confirmed");
                            return View();
                        }

                        await _userManager.ResetAccessFailedCountAsync(user);

                        if (await _userManager.GetTwoFactorEnabledAsync(user))
                        {
                            var validProviders = await _userManager
                                .GetValidTwoFactorProvidersAsync(user);

                            if (validProviders.Contains(_userManager.Options
                                .Tokens.AuthenticatorTokenProvider))
                            {
                                await HttpContext.SignInAsync(
                                    IdentityConstants.TwoFactorUserIdScheme,
                                    Store2FA(user.Id, _userManager.Options.Tokens.AuthenticatorTokenProvider));
                                return RedirectToAction("TwoFactor");
                            }

                            if (validProviders.Contains("Email"))
                            {
                                var token = await
                                    _userManager.GenerateTwoFactorTokenAsync(
                                        user, "Email");
                                System.IO.File.WriteAllText("email2sv.txt", token);

                                await HttpContext.SignInAsync(
                                    IdentityConstants.TwoFactorUserIdScheme,
                                    Store2FA(user.Id, "Email"));
                                return RedirectToAction("TwoFactor");
                            }
                        }

                        //var signInResult = await _signInManager.PasswordSignInAsync(
                        //    model.UserName, model.Password,
                        //    false, false);
                        //if (signInResult.Succeeded)
                        //{
                        //    return RedirectToAction("Index");
                        //}

                        var principal =
                            await _claimsPrincipalFactory.CreateAsync(user);

                        await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme,
                            principal);

                        return RedirectToAction("Index");
                    }

                    await _userManager.AccessFailedAsync(user);

                    if (await _userManager.IsLockedOutAsync(user))
                    {

                        // send email to user to inform about be locked out
                    }
                }
                ModelState.AddModelError("", "Invalid UserName or Password");
            }

            return View();
        }

        private ClaimsPrincipal Store2FA(string userId, string provider)
        {
            var identity = new ClaimsIdentity(new List<Claim>
            {
                new Claim("sub", userId),
                new Claim("amr", provider) // authentication method reference
            }, IdentityConstants.TwoFactorUserIdScheme);

            return new ClaimsPrincipal(identity);
        }

        [HttpGet]
        public IActionResult ForgotPassword()
        {
            return View();
        }


        [HttpPost]
        public async Task<IActionResult> ForgotPassword(
            ForgotPasswordModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user != null)
                {
                    var token =
                        await _userManager
                            .GeneratePasswordResetTokenAsync(user);

                    var resetUrl = Url.Action("ResetPassword", "Home",
                        new { token = token, email = user.Email },
                        Request.Scheme);

                    System.IO.File.WriteAllText("resetLink.txt", resetUrl);
                }

                else
                {
                    // email user and inform them they don't have an account
                }

                return View("Success");
            }

            return View();
        }

        [HttpGet]
        public IActionResult ResetPassword(string token, string email)
        {
            return View(new ResetPasswordModel { Token = token, Email = email });
        }

        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPasswordModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (user != null)
                {
                    var result = await _userManager.ResetPasswordAsync(user,
                        model.Token, model.Password);

                    if (!result.Succeeded)
                    {
                        foreach (var error in result.Errors)
                        {
                            ModelState.AddModelError("", error.Description);
                        }
                        return View();
                    }

                    if (await _userManager.IsLockedOutAsync(user))
                    {
                        await _userManager.SetLockoutEndDateAsync(user, DateTimeOffset.UtcNow);
                    }

                    return View("Success");
                }
                ModelState.AddModelError("", "Invalid Request");
            }

            return View();
        }

        [HttpGet]
        public IActionResult TwoFactor()
        {
            return View();
        }

        [HttpPost]
        public async Task<IActionResult> TwoFactor(TwoFactorModel model)
        {
            var result =
                await HttpContext.AuthenticateAsync(IdentityConstants
                    .TwoFactorUserIdScheme);
            if (!result.Succeeded)
            {
                ModelState.AddModelError("","Your login request has expired, please start over");
                return View();
            }

            if (ModelState.IsValid)
            {
                var user =
                    await _userManager.FindByIdAsync(
                        result.Principal.FindFirstValue("sub"));

                if (user != null)
                {
                    var isValid =
                        await _userManager.VerifyTwoFactorTokenAsync(user,
                            result.Principal.FindFirstValue("amr"), model.Token);

                    if (isValid)
                    {
                        await HttpContext.SignOutAsync(IdentityConstants
                            .TwoFactorUserIdScheme);

                        var claimsPrincipal =
                            await _claimsPrincipalFactory.CreateAsync(user);
                        await HttpContext.SignInAsync(
                            IdentityConstants.ApplicationScheme,
                            claimsPrincipal);

                        return RedirectToAction("Index");
                    }

                    ModelState.AddModelError("","Invalid Token");

                    return View();
                }

                ModelState.AddModelError("", "Invalid Request");

            }

            return View();
        }

        [HttpGet]
        [Authorize]
        public async Task<IActionResult> RegisterAuthenticator()
        {
            var user = await _userManager.GetUserAsync(User);

            var authenticatorKey =
                await _userManager.GetAuthenticatorKeyAsync(user);

            if (authenticatorKey == null)
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                authenticatorKey =
                    await _userManager.GetAuthenticatorKeyAsync(user);
            }

            return View(new RegisterAuthenticatorModel()
            {
                AuthenticatorKey = authenticatorKey
            });
        }

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> RegisterAuthenticator(
            RegisterAuthenticatorModel model)
        {
            var user = await _userManager.GetUserAsync(User);

            var isValid = await _userManager.VerifyTwoFactorTokenAsync(user,
                _userManager.Options.Tokens.AuthenticatorTokenProvider,
                model.Code);

            if (!isValid)
            {
                ModelState.AddModelError("", "Code is invalid");
                return View(model);
            }

            await _userManager.SetTwoFactorEnabledAsync(user, true);
            return View("Success");
        }

        public IActionResult ExternalLogin(string provider)
        {
            var properties  = new AuthenticationProperties
            {
                RedirectUri = Url.Action("ExternalLoginCallBack"),
                Items = { { "scheme", provider} }
            };

            return Challenge(properties, provider);
        }

        public async Task<IActionResult> ExternalLoginCallBack()
        {
            var result =
                await HttpContext.AuthenticateAsync(IdentityConstants
                    .ExternalScheme);

            var externalUserId = result.Principal.FindFirstValue("sub")
                                 ?? result.Principal.FindFirstValue(ClaimTypes
                                     .NameIdentifier)
                                 ?? throw new Exception(
                                     "Cannot find external user id");

            var provider = result.Properties.Items["scheme"];

            var user =
                await _userManager.FindByLoginAsync(provider, externalUserId);

            if (user == null)
            {
                var email = result.Principal.FindFirstValue("email")
                            ?? result.Principal
                                .FindFirstValue(ClaimTypes.Email);

                if (email != null)
                {
                    user = await _userManager.FindByEmailAsync(email);

                    if (user == null)
                    {
                        user = new PluralsightUser(){Email = email, UserName = email};
                        await _userManager.CreateAsync(user);
                    }

                    await _userManager.AddLoginAsync(user,
                        new UserLoginInfo(provider, externalUserId, provider));
                }
            }

            if (user == null) return View("Error");

            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            var claimsPrincipal =
                await _claimsPrincipalFactory.CreateAsync(user);

            await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, claimsPrincipal);

            return RedirectToAction("Index");
        }
    }
}
