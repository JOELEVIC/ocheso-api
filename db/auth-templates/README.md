# Auth email templates

`code.html` is the template for both **Confirm signup** and **Magic Link** in the
Supabase dashboard (Authentication > Emails > Templates). Subject for both:

    Your Ocheso code: {{ .Token }} / Votre code Ocheso

Embeds sign people in with the 6-digit code (spec E4); Supabase's default
templates carry only a link, so without this change nobody can join from an
embed. Requires custom SMTP (Resend) too — the built-in mailer sends a handful
of emails an hour.
