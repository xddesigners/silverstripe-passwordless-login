<div style="font-family: Arial, Helvetica, sans-serif; font-size: 15px; color: #222; line-height: 1.5;">
    <p><%t XD\PasswordlessLogin\Delivery\EmailDelivery.Greeting 'Hi {name},' name=$Member.FirstName %></p>

    <p><%t XD\PasswordlessLogin\Delivery\EmailDelivery.Intro 'Use this code to log in:' %></p>

    <p style="font-size: 30px; font-weight: bold; letter-spacing: 6px; margin: 20px 0;">$Code</p>

    <p style="color: #666;">
        <%t XD\PasswordlessLogin\Delivery\EmailDelivery.Expiry 'This code is valid for {minutes} minutes and can be used once.' minutes=$TtlMinutes %>
    </p>

    <p style="color: #666;">
        <%t XD\PasswordlessLogin\Delivery\EmailDelivery.Ignore 'Did you not request this? Then you can safely ignore this e-mail.' %>
    </p>
</div>
