# NoTPK.Owin.Security.ObsidianPortal
NoTPK.Owin.Security.ObsidianPortal is an [OWIN](http://owin.org/) authentication provider for [Obsidian Portal](http://www.obsidianportal.com)

## Installation via NuGet Package

Create an Obsidian Portal app to get your unique Client ID and Client Secret from: [https://www.obsidianportal.com/oauth/clients/new](https://www.obsidianportal.com/oauth/clients/new)

	Install-Package NoTPK.Owin.Security.ObsidianPortal

	Add the following to Startup.Auth.cs (VS2013) or AuthConfig.cs (VS2012):

            app.UseObsidianPortalAuthentication(
                clientId: "",
                clientSecret: "");


### Attribution

[This product includes software developed at: Microsoft Open Technologies, Inc.](https://github.com/johndpalm/Citrius.Owin.Security.Foursquare/blob/master/NOTICE.txt)

### License
[Apache v2 License](https://github.com/johndpalm/Citrius.Owin.Security.Foursquare/blob/master/LICENSE.txt)
