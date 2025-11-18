import tensorflow as tf

print('=== VERIFICACIÓN COMPLETA ===')
print('TensorFlow version:', tf.__version__)
print('GPUs disponibles:', tf.config.list_physical_devices('GPU'))
print('Todos los dispositivos:', tf.config.list_physical_devices())

# Verificación detallada
if tf.config.list_physical_devices('GPU'):
    print('✅ ¡ÉXITO! TensorFlow está usando la GPU')
    gpu_name = tf.test.gpu_device_name()
    print('Dispositivo GPU:', gpu_name)

    # Probar con una operación simple
    with tf.device('/GPU:0'):
        a = tf.constant([[1.0, 2.0], [3.0, 4.0]])
        b = tf.constant([[1.0, 1.0], [0.0, 1.0]])
        c = tf.matmul(a, b)
        print('Multiplicación de matrices en GPU:', c.numpy())
else:
    print('❌ TensorFlow NO detecta la GPU')
    print('Posibles soluciones:')
    print('1. Reiniciar el sistema')
    print('2. Verificar que CUDA_PATH esté configurado')