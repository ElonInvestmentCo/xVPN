import React, { useEffect } from 'react';
import { View, StyleSheet, Dimensions, Platform } from 'react-native';
import Svg, { Circle, Line, Path, G, Rect } from 'react-native-svg';
import Animated, {
  useSharedValue,
  useAnimatedStyle,
  withRepeat,
  withTiming,
  Easing,
} from 'react-native-reanimated';
import Colors from '@/constants/colors';
import type { VpnServer } from '@/lib/vpn-context';

const { width: SCREEN_WIDTH } = Dimensions.get('window');
const MAP_WIDTH = SCREEN_WIDTH - 40;
const MAP_HEIGHT = MAP_WIDTH * 0.48;

interface CityNode {
  serverId: string;
  x: number;
  y: number;
  name: string;
}

const CITY_NODES: CityNode[] = [
  { serverId: '1', x: 0.22, y: 0.32, name: 'New York' },
  { serverId: '2', x: 0.12, y: 0.35, name: 'Los Angeles' },
  { serverId: '3', x: 0.47, y: 0.28, name: 'London' },
  { serverId: '4', x: 0.52, y: 0.30, name: 'Frankfurt' },
  { serverId: '5', x: 0.85, y: 0.38, name: 'Tokyo' },
  { serverId: '6', x: 0.78, y: 0.58, name: 'Singapore' },
  { serverId: '7', x: 0.88, y: 0.78, name: 'Sydney' },
  { serverId: '8', x: 0.18, y: 0.28, name: 'Toronto' },
  { serverId: '9', x: 0.50, y: 0.29, name: 'Amsterdam' },
  { serverId: '10', x: 0.51, y: 0.32, name: 'Zurich' },
  { serverId: '11', x: 0.49, y: 0.31, name: 'Paris' },
  { serverId: '12', x: 0.82, y: 0.36, name: 'Seoul' },
  { serverId: '13', x: 0.28, y: 0.68, name: 'Sao Paulo' },
  { serverId: '14', x: 0.70, y: 0.48, name: 'Mumbai' },
  { serverId: '15', x: 0.53, y: 0.24, name: 'Stockholm' },
];

function PingNode({ cx, cy, isSelected, isConnected }: { cx: number; cy: number; isSelected: boolean; isConnected: boolean }) {
  const pingScale = useSharedValue(1);
  const pingOpacity = useSharedValue(0.6);

  useEffect(() => {
    if (isSelected && isConnected) {
      pingScale.value = withRepeat(withTiming(3, { duration: 1500, easing: Easing.out(Easing.ease) }), -1, false);
      pingOpacity.value = withRepeat(withTiming(0, { duration: 1500, easing: Easing.out(Easing.ease) }), -1, false);
    } else if (isSelected) {
      pingScale.value = withRepeat(withTiming(2.5, { duration: 2000, easing: Easing.out(Easing.ease) }), -1, false);
      pingOpacity.value = withRepeat(withTiming(0, { duration: 2000, easing: Easing.out(Easing.ease) }), -1, false);
    } else {
      pingScale.value = withTiming(1);
      pingOpacity.value = withTiming(0.4);
    }
  }, [isSelected, isConnected]);

  const pingStyle = useAnimatedStyle(() => ({
    position: 'absolute' as const,
    left: cx - 12,
    top: cy - 12,
    width: 24,
    height: 24,
    borderRadius: 12,
    borderWidth: 1,
    borderColor: isConnected && isSelected ? '#00E676' : Colors.dark.accent,
    opacity: pingOpacity.value,
    transform: [{ scale: pingScale.value }],
  }));

  return isSelected ? <Animated.View style={pingStyle} /> : null;
}

interface WorldMapProps {
  selectedServer: VpnServer | null;
  isConnected: boolean;
}

export function WorldMap({ selectedServer, isConnected }: WorldMapProps) {
  const selectedNode = CITY_NODES.find(n => n.serverId === selectedServer?.id);

  const continentPaths = [
    'M 60 75 Q 80 60 100 65 Q 110 55 95 50 Q 80 45 70 50 Q 55 55 45 65 Q 50 75 60 75 Z',
    'M 155 60 Q 180 45 210 55 Q 230 65 220 80 Q 200 95 175 85 Q 160 75 155 60 Z',
    'M 260 80 Q 290 70 320 75 Q 340 85 330 100 Q 310 115 280 105 Q 260 95 260 80 Z',
    'M 320 100 Q 350 90 370 100 Q 380 115 365 130 Q 340 140 325 125 Q 315 110 320 100 Z',
    'M 80 110 Q 100 100 120 115 Q 115 140 95 145 Q 80 135 75 120 Q 78 112 80 110 Z',
  ];

  return (
    <View style={styles.container}>
      <View style={[styles.mapContainer, { width: MAP_WIDTH, height: MAP_HEIGHT }]}>
        <Svg width={MAP_WIDTH} height={MAP_HEIGHT} viewBox={`0 0 ${MAP_WIDTH} ${MAP_HEIGHT}`}>
          <Rect x={0} y={0} width={MAP_WIDTH} height={MAP_HEIGHT} fill="transparent" />

          {Array.from({ length: 8 }).map((_, i) => (
            <Line
              key={`grid-h-${i}`}
              x1={0}
              y1={(MAP_HEIGHT / 8) * (i + 1)}
              x2={MAP_WIDTH}
              y2={(MAP_HEIGHT / 8) * (i + 1)}
              stroke="rgba(255,255,255,0.02)"
              strokeWidth={0.5}
            />
          ))}
          {Array.from({ length: 12 }).map((_, i) => (
            <Line
              key={`grid-v-${i}`}
              x1={(MAP_WIDTH / 12) * (i + 1)}
              y1={0}
              x2={(MAP_WIDTH / 12) * (i + 1)}
              y2={MAP_HEIGHT}
              stroke="rgba(255,255,255,0.02)"
              strokeWidth={0.5}
            />
          ))}

          {CITY_NODES.map(node => {
            const nx = node.x * MAP_WIDTH;
            const ny = node.y * MAP_HEIGHT;
            const isSelected = node.serverId === selectedServer?.id;

            if (isSelected && selectedNode) {
              return (
                <G key={node.serverId}>
                  <Circle cx={nx} cy={ny} r={isConnected ? 5 : 4} fill={isConnected ? '#00E676' : Colors.dark.accent} opacity={0.9} />
                  <Circle cx={nx} cy={ny} r={2} fill="#fff" opacity={0.8} />
                </G>
              );
            }

            return (
              <G key={node.serverId}>
                <Circle cx={nx} cy={ny} r={2.5} fill={Colors.dark.accent} opacity={0.35} />
                <Circle cx={nx} cy={ny} r={1} fill={Colors.dark.accent} opacity={0.6} />
              </G>
            );
          })}

          {isConnected && selectedNode && (
            <>
              <Line
                x1={MAP_WIDTH * 0.5}
                y1={MAP_HEIGHT * 0.5}
                x2={selectedNode.x * MAP_WIDTH}
                y2={selectedNode.y * MAP_HEIGHT}
                stroke={Colors.dark.accent}
                strokeWidth={0.5}
                strokeDasharray="4 4"
                opacity={0.3}
              />
              <Circle
                cx={MAP_WIDTH * 0.5}
                cy={MAP_HEIGHT * 0.5}
                r={3}
                fill={Colors.dark.accentPurple}
                opacity={0.5}
              />
            </>
          )}
        </Svg>

        {CITY_NODES.map(node => {
          const nx = node.x * MAP_WIDTH;
          const ny = node.y * MAP_HEIGHT;
          const isSelected = node.serverId === selectedServer?.id;
          return (
            <PingNode
              key={`ping-${node.serverId}`}
              cx={nx}
              cy={ny}
              isSelected={isSelected}
              isConnected={isConnected}
            />
          );
        })}
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    alignItems: 'center',
    paddingHorizontal: 20,
  },
  mapContainer: {
    backgroundColor: 'rgba(255,255,255,0.02)',
    borderRadius: 16,
    borderWidth: 1,
    borderColor: 'rgba(255,255,255,0.04)',
    overflow: 'hidden',
    ...(Platform.OS === 'web' ? {
      // @ts-ignore
      backdropFilter: 'blur(10px)',
    } : {}),
  },
});
