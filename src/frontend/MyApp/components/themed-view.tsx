import { View, type ViewProps, StyleSheet } from 'react-native';
import { useThemeColor } from '@/hooks/use-theme-color';

export type ThemedViewProps = ViewProps & {
  lightColor?: string;
  darkColor?: string;
};

export function ThemedView({ style, lightColor, darkColor, ...otherProps }: ThemedViewProps) {
  const backgroundColor = useThemeColor({ light: lightColor, dark: darkColor }, 'background');
  // Flatten the array into a single object
  const combinedStyle = StyleSheet.flatten([{ backgroundColor }, style]);
  return <View style={combinedStyle} {...otherProps} />;
}