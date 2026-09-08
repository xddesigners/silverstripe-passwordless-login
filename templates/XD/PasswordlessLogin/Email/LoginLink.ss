<div style="font-family: Arial, Helvetica, sans-serif; font-size: 15px; color: #222; line-height: 1.5;">
    <p><%t XD\PasswordlessLogin\Delivery\EmailDelivery.Greeting 'Hi {name},' name=$Member.FirstName %></p>

    <p><%t XD\PasswordlessLogin\Delivery\EmailDelivery.LinkIntro 'Click the button below to log in:' %></p>

    <p style="margin: 24px 0;">
        <a href="$Url" style="background: #2563eb; color: #fff; text-decoration: none; padding: 12px 20px; border-radius: 6px; display: inline-block; font-weight: bold;">
            <%t XD\PasswordlessLogin\Delivery\EmailDelivery.LinkButton 'Log in' %>
        </a>
    </p>

    <p style="color: #666;">
        <%t XD\PasswordlessLogin\Delivery\EmailDelivery.LinkExpiry 'This link is valid for {minutes} minutes and can be used once.' minutes=$TtlMinutes %>
    </p>

    <p style="color: #666; word-break: break-all;">
        <%t XD\PasswordlessLogin\Delivery\EmailDelivery.LinkFallback 'If the button does not work, copy this address into your browser:' %><br>
        $Url
    </p>

    <p style="color: #666;">
        <%t XD\PasswordlessLogin\Delivery\EmailDelivery.Ignore 'Did you not request this? Then you can safely ignore this e-mail.' %>
    </p>
</div>
