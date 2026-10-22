package io.github.yanngc32.velora

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Text
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.Font
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** The desktop launcher's look (crates/client/src/gui/theme.rs), so both apps match. */
object Velora {
    val Bg = Color(0xFF0F1014)
    val Sidebar = Color(0xFF14151B)
    val Card = Color(0xFF1A1B22)
    val Hover = Color(0xFF21222B)
    val Border = Color(0xFF2B2D38)
    val BorderStrong = Color(0xFF3A3C4A)
    val Text = Color(0xFFE6E7EE)
    val Weak = Color(0xFF989AAB)
    val Faint = Color(0xFF6B6D7E)
    /** Brand violet: the main action and the current selection. */
    val Accent = Color(0xFF7B4DFF)
    val AccentPressed = Color(0xFF693CE8)
    /** Lavender: accent text on dark surfaces. */
    val AccentText = Color(0xFFB388FF)
    /** Teal: live status. */
    val Live = Color(0xFF4EE1C3)
    val Error = Color(0xFFF26D7D)

    val Radius = RoundedCornerShape(6.dp)
    val CardRadius = RoundedCornerShape(10.dp)
    val ControlHeight = 44.dp

    val Inter = FontFamily(
        Font(R.font.inter_regular, FontWeight.Normal),
        Font(R.font.inter_medium, FontWeight.Medium),
        Font(R.font.inter_semibold, FontWeight.SemiBold),
        Font(R.font.inter_bold, FontWeight.Bold),
    )
    val Mono = FontFamily(Font(R.font.jetbrains_mono))
}

private val Colors = darkColorScheme(
    primary = Velora.Accent,
    onPrimary = Color.White,
    secondary = Velora.AccentText,
    onSecondary = Velora.Bg,
    tertiary = Velora.Live,
    background = Velora.Bg,
    onBackground = Velora.Text,
    surface = Velora.Bg,
    onSurface = Velora.Text,
    surfaceVariant = Velora.Card,
    onSurfaceVariant = Velora.Weak,
    surfaceContainerHigh = Velora.Card,
    outline = Velora.BorderStrong,
    error = Velora.Error,
)

private fun inter(size: Int, weight: FontWeight = FontWeight.Normal) =
    TextStyle(fontFamily = Velora.Inter, fontWeight = weight, fontSize = size.sp)

private val Type = Typography(
    headlineMedium = inter(28, FontWeight.Bold).copy(letterSpacing = (-0.4).sp),
    titleMedium = inter(15, FontWeight.SemiBold),
    titleSmall = inter(14, FontWeight.SemiBold),
    bodyLarge = inter(15),
    bodyMedium = inter(14),
    bodySmall = inter(13),
    labelLarge = inter(14, FontWeight.SemiBold),
    labelMedium = inter(13, FontWeight.Medium),
    labelSmall = inter(11, FontWeight.SemiBold).copy(letterSpacing = 1.sp),
)

@Composable
fun VeloraTheme(content: @Composable () -> Unit) = MaterialTheme(colorScheme = Colors, typography = Type, content = content)

/** Section label, title and optional subtitle opening each screen (desktop `page_header`). */
@Composable
fun PageHeader(label: String, title: String, subtitle: String? = null) {
    Column {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Box(Modifier.width(16.dp).height(2.dp).background(Velora.AccentText))
            Spacer(Modifier.width(8.dp))
            Text(label.uppercase(), style = MaterialTheme.typography.labelSmall, color = Velora.AccentText)
        }
        Spacer(Modifier.height(4.dp))
        Text(title, style = MaterialTheme.typography.headlineMedium, color = Velora.Text)
        if (subtitle != null) {
            Spacer(Modifier.height(2.dp))
            Text(subtitle, style = MaterialTheme.typography.bodyLarge, color = Velora.Weak)
        }
    }
}

@Composable
fun VeloraCard(modifier: Modifier = Modifier, padding: PaddingValues = PaddingValues(20.dp), content: @Composable ColumnScope.() -> Unit) {
    Column(
        modifier
            .fillMaxWidth()
            .background(Velora.Card, Velora.CardRadius)
            .border(1.dp, Velora.Border, Velora.CardRadius)
            .padding(padding),
        content = content,
    )
}

@Composable
fun PrimaryButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier, enabled: Boolean = true, icon: Int? = null) {
    Button(
        onClick = onClick,
        enabled = enabled,
        modifier = modifier.height(Velora.ControlHeight),
        shape = Velora.Radius,
        colors = ButtonDefaults.buttonColors(
            containerColor = Velora.Accent,
            contentColor = Color.White,
            disabledContainerColor = Velora.Hover,
            disabledContentColor = Velora.Faint,
        ),
        contentPadding = PaddingValues(horizontal = 16.dp),
    ) {
        ButtonContent(text, icon)
    }
}

@Composable
fun SecondaryButton(text: String, onClick: () -> Unit, modifier: Modifier = Modifier, icon: Int? = null) {
    OutlinedButton(
        onClick = onClick,
        modifier = modifier.height(Velora.ControlHeight),
        shape = Velora.Radius,
        border = BorderStroke(1.dp, Velora.BorderStrong),
        colors = ButtonDefaults.outlinedButtonColors(contentColor = Velora.Text),
        contentPadding = PaddingValues(horizontal = 14.dp),
    ) {
        ButtonContent(text, icon, weight = FontWeight.Medium)
    }
}

@Composable
private fun ButtonContent(text: String, icon: Int?, weight: FontWeight = FontWeight.SemiBold) {
    if (icon != null) {
        Icon(painterResource(icon), contentDescription = null, modifier = Modifier.size(16.dp))
        Spacer(Modifier.width(8.dp))
    }
    Text(text, style = MaterialTheme.typography.labelLarge.copy(fontWeight = weight))
}

/** A colored dot followed by a label, e.g. "● Connected" (desktop `status`). */
@Composable
fun StatusDot(text: String, color: Color) {
    Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        Canvas(Modifier.size(7.dp)) { drawCircle(color) }
        Text(text, style = MaterialTheme.typography.labelMedium, color = color)
    }
}

/** A labelled single-line field; `technical` sets it in monospace, for codes and addresses. */
@Composable
fun Field(
    label: String,
    value: String,
    onValueChange: (String) -> Unit,
    placeholder: String = "",
    technical: Boolean = false,
    password: Boolean = false,
) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Text(label, style = MaterialTheme.typography.labelMedium, color = Velora.Weak)
        OutlinedTextField(
            value = value,
            onValueChange = onValueChange,
            singleLine = true,
            placeholder = { Text(placeholder, color = Velora.Faint, style = MaterialTheme.typography.bodyMedium) },
            textStyle = if (technical) TextStyle(fontFamily = Velora.Mono, fontSize = 13.sp, color = Velora.Text)
            else MaterialTheme.typography.bodyMedium.copy(color = Velora.Text),
            visualTransformation = if (password) PasswordVisualTransformation() else VisualTransformation.None,
            keyboardOptions = if (password) KeyboardOptions(keyboardType = KeyboardType.Password) else KeyboardOptions.Default,
            shape = Velora.Radius,
            colors = OutlinedTextFieldDefaults.colors(
                focusedContainerColor = Velora.Bg,
                unfocusedContainerColor = Velora.Bg,
                focusedBorderColor = Velora.Accent,
                unfocusedBorderColor = Velora.Border,
                cursorColor = Velora.AccentText,
            ),
            modifier = Modifier.fillMaxWidth(),
        )
    }
}

/** A square tile with an icon, like the device rows on the desktop. */
@Composable
fun IconTile(icon: Int, size: Int = 40) {
    Box(
        Modifier.size(size.dp).background(Velora.Bg, Velora.Radius).border(1.dp, Velora.Border, Velora.Radius),
        contentAlignment = Alignment.Center,
    ) {
        Icon(painterResource(icon), contentDescription = null, tint = Velora.Weak, modifier = Modifier.size((size / 2).dp))
    }
}
