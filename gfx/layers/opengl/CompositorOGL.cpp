/* -*- Mode: C++; tab-width: 20; indent-tabs-mode: nil; c-basic-offset: 2 -*-
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include "CompositorOGL.h"
#include "TextureOGL.h"
#include "mozilla/Preferences.h"

#include "gfxUtils.h"

#include "GLContextProvider.h"

#include "nsIServiceManager.h"
#include "nsIConsoleService.h"

#include "gfxCrashReporterUtils.h"

namespace mozilla {
namespace layers {

using namespace mozilla::gl;

CompositorOGL::CompositorOGL(nsIWidget *aWidget, int aSurfaceWidth,
                             int aSurfaceHeight, bool aIsRenderingToEGLSurface)
  : mWidget(aWidget)
  , mSurfaceSize(aSurfaceWidth, aSurfaceHeight)
  , mBackBufferFBO(0)
  , mBackBufferTexture(0)
  , mHasBGRA(0)
  , mIsRenderingToEGLSurface(aIsRenderingToEGLSurface)
  , mDestroyed(false)
{
}

already_AddRefed<mozilla::gl::GLContext>
CompositorOGL::CreateContext()
{
  nsRefPtr<GLContext> context;

#ifdef XP_WIN
  if (PR_GetEnv("MOZ_LAYERS_PREFER_EGL")) {
    printf_stderr("Trying GL layers...\n");
    context = gl::GLContextProviderEGL::CreateForWindow(mWidget);
  }
#endif

  if (!context)
    context = gl::GLContextProvider::CreateForWindow(mWidget);

  if (!context) {
    NS_WARNING("Failed to create LayerManagerOGL context");
  }
  return context.forget();
}

void
CompositorOGL::AddPrograms(ShaderProgramType aType)
{
  for (PRUint32 maskType = MaskNone; maskType < NumMaskTypes; ++maskType) {
    if (ProgramProfileOGL::ProgramExists(aType, static_cast<MaskType>(maskType))) {
      mPrograms[aType].mVariations[maskType] = new ShaderProgramOGL(this->gl(),
        ProgramProfileOGL::GetProfileFor(aType, static_cast<MaskType>(maskType)));
    } else {
      mPrograms[aType].mVariations[maskType] = nsnull;
    }
  }
}

void
CompositorOGL::Destroy()
{
  mDestroyed = true;

  // TODO: Cleanup resources here.
}

bool
CompositorOGL::Initialize(bool force, nsRefPtr<GLContext> aContext)
{
  ScopedGfxFeatureReporter reporter("GL Layers", force);

  // Do not allow double initialization
  NS_ABORT_IF_FALSE(mGLContext == nsnull, "Don't reinitialize CompositorOGL");

  if (aContext) {
    mGLContext = aContext;
  } else {
    mGLContext = CreateContext();
  }

#ifdef MOZ_WIDGET_ANDROID
  if (!mGLContext)
    NS_RUNTIMEABORT("We need a context on Android");
#endif

  if (!mGLContext)
    return false;

  mGLContext = aContext;
  mGLContext->SetFlipped(true);

  MakeCurrent();

  mHasBGRA =
    mGLContext->IsExtensionSupported(gl::GLContext::EXT_texture_format_BGRA8888) ||
    mGLContext->IsExtensionSupported(gl::GLContext::EXT_bgra);

  mGLContext->fBlendFuncSeparate(LOCAL_GL_ONE, LOCAL_GL_ONE_MINUS_SRC_ALPHA,
                                 LOCAL_GL_ONE, LOCAL_GL_ONE);
  mGLContext->fEnable(LOCAL_GL_BLEND);

  mPrograms.AppendElements(NumProgramTypes);
  for (int type = 0; type < NumProgramTypes; ++type) {
    AddPrograms(static_cast<ShaderProgramType>(type));
  }

  // initialise a common shader to check that we can actually compile a shader
  if (!mPrograms[gl::RGBALayerProgramType].mVariations[MaskNone]->Initialize()) {
    return false;
  }


  mGLContext->fGenFramebuffers(1, &mBackBufferFBO);

  if (mGLContext->WorkAroundDriverBugs()) {

    /**
    * We'll test the ability here to bind NPOT textures to a framebuffer, if
    * this fails we'll try ARB_texture_rectangle.
    */

    GLenum textureTargets[] = {
      LOCAL_GL_TEXTURE_2D,
      LOCAL_GL_NONE
    };

    if (mGLContext->IsGLES2()) {
        textureTargets[1] = LOCAL_GL_TEXTURE_RECTANGLE_ARB;
    }

    mFBOTextureTarget = LOCAL_GL_NONE;

    for (PRUint32 i = 0; i < ArrayLength(textureTargets); i++) {
      GLenum target = textureTargets[i];
      if (!target)
          continue;

      mGLContext->fGenTextures(1, &mBackBufferTexture);
      mGLContext->fBindTexture(target, mBackBufferTexture);
      mGLContext->fTexParameteri(target,
                                LOCAL_GL_TEXTURE_MIN_FILTER,
                                LOCAL_GL_NEAREST);
      mGLContext->fTexParameteri(target,
                                LOCAL_GL_TEXTURE_MAG_FILTER,
                                LOCAL_GL_NEAREST);
      mGLContext->fTexImage2D(target,
                              0,
                              LOCAL_GL_RGBA,
                              5, 3, /* sufficiently NPOT */
                              0,
                              LOCAL_GL_RGBA,
                              LOCAL_GL_UNSIGNED_BYTE,
                              NULL);

      // unbind this texture, in preparation for binding it to the FBO
      mGLContext->fBindTexture(target, 0);

      mGLContext->fBindFramebuffer(LOCAL_GL_FRAMEBUFFER, mBackBufferFBO);
      mGLContext->fFramebufferTexture2D(LOCAL_GL_FRAMEBUFFER,
                                        LOCAL_GL_COLOR_ATTACHMENT0,
                                        target,
                                        mBackBufferTexture,
                                        0);

      if (mGLContext->fCheckFramebufferStatus(LOCAL_GL_FRAMEBUFFER) ==
          LOCAL_GL_FRAMEBUFFER_COMPLETE)
      {
        mFBOTextureTarget = target;
        break;
      }

      // We weren't succesful with this texture, so we don't need it
      // any more.
      mGLContext->fDeleteTextures(1, &mBackBufferTexture);
    }

    if (mFBOTextureTarget == LOCAL_GL_NONE) {
      /* Unable to find a texture target that works with FBOs and NPOT textures */
      return false;
    }
  } else {
    // not trying to work around driver bugs, so TEXTURE_2D should just work
    mFBOTextureTarget = LOCAL_GL_TEXTURE_2D;
  }

  // back to default framebuffer, to avoid confusion
  mGLContext->fBindFramebuffer(LOCAL_GL_FRAMEBUFFER, 0);

  if (mFBOTextureTarget == LOCAL_GL_TEXTURE_RECTANGLE_ARB) {
    /* If we're using TEXTURE_RECTANGLE, then we must have the ARB
     * extension -- the EXT variant does not provide support for
     * texture rectangle access inside GLSL (sampler2DRect,
     * texture2DRect).
     */
    if (!mGLContext->IsExtensionSupported(gl::GLContext::ARB_texture_rectangle))
      return false;
  }

  // If we're double-buffered, we don't need this fbo anymore.
  if (mGLContext->IsDoubleBuffered()) {
    mGLContext->fDeleteFramebuffers(1, &mBackBufferFBO);
    mBackBufferFBO = 0;
  }

  /* Create a simple quad VBO */

  mGLContext->fGenBuffers(1, &mQuadVBO);
  mGLContext->fBindBuffer(LOCAL_GL_ARRAY_BUFFER, mQuadVBO);

  GLfloat vertices[] = {
    /* First quad vertices */
    0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 1.0f, 1.0f, 1.0f,
    /* Then quad texcoords */
    0.0f, 0.0f, 1.0f, 0.0f, 0.0f, 1.0f, 1.0f, 1.0f,
    /* Then flipped quad texcoords */
    0.0f, 1.0f, 1.0f, 1.0f, 0.0f, 0.0f, 1.0f, 0.0f,
  };
  mGLContext->fBufferData(LOCAL_GL_ARRAY_BUFFER, sizeof(vertices), vertices, LOCAL_GL_STATIC_DRAW);
  mGLContext->fBindBuffer(LOCAL_GL_ARRAY_BUFFER, 0);

  nsCOMPtr<nsIConsoleService>
    console(do_GetService(NS_CONSOLESERVICE_CONTRACTID));

  if (console) {
    nsString msg;
    msg +=
      NS_LITERAL_STRING("OpenGL LayerManager Initialized Succesfully.\nVersion: ");
    msg += NS_ConvertUTF8toUTF16(
      nsDependentCString((const char*)mGLContext->fGetString(LOCAL_GL_VERSION)));
    msg += NS_LITERAL_STRING("\nVendor: ");
    msg += NS_ConvertUTF8toUTF16(
      nsDependentCString((const char*)mGLContext->fGetString(LOCAL_GL_VENDOR)));
    msg += NS_LITERAL_STRING("\nRenderer: ");
    msg += NS_ConvertUTF8toUTF16(
      nsDependentCString((const char*)mGLContext->fGetString(LOCAL_GL_RENDERER)));
    msg += NS_LITERAL_STRING("\nFBO Texture Target: ");
    if (mFBOTextureTarget == LOCAL_GL_TEXTURE_2D)
      msg += NS_LITERAL_STRING("TEXTURE_2D");
    else
      msg += NS_LITERAL_STRING("TEXTURE_RECTANGLE");
    console->LogStringMessage(msg.get());
  }

  if (NS_IsMainThread()) {
    Preferences::AddBoolVarCache(&sDrawFPS, "layers.acceleration.draw-fps");
  } else {
    // We have to dispatch an event to the main thread to read the pref.
    class ReadDrawFPSPref : public nsRunnable {
    public:
      NS_IMETHOD Run()
      {
        Preferences::AddBoolVarCache(&sDrawFPS, "layers.acceleration.draw-fps");
        return NS_OK;
      }
    };
    NS_DispatchToMainThread(new ReadDrawFPSPref());
  }

  reporter.SetSuccessful();
  return true;
}

// |aTexCoordRect| is the rectangle from the texture that we want to
// draw using the given program.  The program already has a necessary
// offset and scale, so the geometry that needs to be drawn is a unit
// square from 0,0 to 1,1.
//
// |aTexSize| is the actual size of the texture, as it can be larger
// than the rectangle given by |aTexCoordRect|.
void 
CompositorOGL::BindAndDrawQuadWithTextureRect(ShaderProgramOGL *aProg,
                                                const gfx::IntRect& aTexCoordRect,
                                                const nsIntSize& aTexSize,
                                                GLenum aWrapMode /* = LOCAL_GL_REPEAT */,
                                                bool aFlipped /* = false */)
{
  NS_ASSERTION(aProg->HasInitialized(), "Shader program not correctly initialized");
  GLuint vertAttribIndex =
    aProg->AttribLocation(ShaderProgramOGL::VertexCoordAttrib);
  GLuint texCoordAttribIndex =
    aProg->AttribLocation(ShaderProgramOGL::TexCoordAttrib);
  NS_ASSERTION(texCoordAttribIndex != GLuint(-1), "no texture coords?");

  // clear any bound VBO so that glVertexAttribPointer() goes back to
  // "pointer mode"
  mGLContext->fBindBuffer(LOCAL_GL_ARRAY_BUFFER, 0);

  // Given what we know about these textures and coordinates, we can
  // compute fmod(t, 1.0f) to get the same texture coordinate out.  If
  // the texCoordRect dimension is < 0 or > width/height, then we have
  // wraparound that we need to deal with by drawing multiple quads,
  // because we can't rely on full non-power-of-two texture support
  // (which is required for the REPEAT wrap mode).

  GLContext::RectTriangles rects;

  nsIntSize realTexSize = aTexSize;
  if (!mGLContext->CanUploadNonPowerOfTwo()) {
    realTexSize = nsIntSize(gfx::NextPowerOfTwo(aTexSize.width),
                            gfx::NextPowerOfTwo(aTexSize.height));
  }

  if (aWrapMode == LOCAL_GL_REPEAT) {
    rects.addRect(/* dest rectangle */
                  0.0f, 0.0f, 1.0f, 1.0f,
                  /* tex coords */
                  aTexCoordRect.x / GLfloat(realTexSize.width),
                  aTexCoordRect.y / GLfloat(realTexSize.height),
                  aTexCoordRect.XMost() / GLfloat(realTexSize.width),
                  aTexCoordRect.YMost() / GLfloat(realTexSize.height),
                  aFlipped);
  } else {
    nsIntRect tcRect(aTexCoordRect.x, aTexCoordRect.y,
                     aTexCoordRect.width, aTexCoordRect.height);
    GLContext::DecomposeIntoNoRepeatTriangles(tcRect, realTexSize,
                                              rects, aFlipped);
  }

  mGLContext->fVertexAttribPointer(vertAttribIndex, 2,
                                   LOCAL_GL_FLOAT, LOCAL_GL_FALSE, 0,
                                   rects.vertexPointer());

  mGLContext->fVertexAttribPointer(texCoordAttribIndex, 2,
                                   LOCAL_GL_FLOAT, LOCAL_GL_FALSE, 0,
                                   rects.texCoordPointer());

  {
    mGLContext->fEnableVertexAttribArray(texCoordAttribIndex);
    {
      mGLContext->fEnableVertexAttribArray(vertAttribIndex);

      mGLContext->fDrawArrays(LOCAL_GL_TRIANGLES, 0, rects.elements());

      mGLContext->fDisableVertexAttribArray(vertAttribIndex);
    }
    mGLContext->fDisableVertexAttribArray(texCoordAttribIndex);
  }
}

TextureHostIdentifier
CompositorOGL::GetTextureHostIdentifier()
{
  // TODO: Implement this.

  return TextureHostIdentifier();
}

TemporaryRef<Texture>
CompositorOGL::CreateTextureForData(const gfx::IntSize &aSize, PRInt8 *aData, PRUint32 aStride,
                                    TextureFormat aFormat)
{
  // TODO: Implement this.
  // TODO: Set GL_TEXTURE_WRAP_T and GL_TEXTURE_WRAP_S here.
  // TODO: Set the Texture's mSize here.

  return new TextureOGL();
}

TemporaryRef<DrawableTextureHost>
CompositorOGL::CreateDrawableTexture(const TextureIdentifier &aIdentifier)
{
  // TODO: Implement this.

  return new DrawableTextureHostOGL();
}

void
CompositorOGL::DrawQuad(const gfx::Rect &aRect, const gfx::Rect *aSourceRect,
                        const gfx::Rect *aClipRect, const EffectChain &aEffectChain,
                        gfx::Float aOpacity, const gfx::Matrix4x4 &aTransform)
{
  gfx::IntRect intSourceRect;
  if (aSourceRect) {
    aSourceRect->ToIntRect(&intSourceRect);
  }

  gfx::IntRect intClipRect;
  if (aClipRect) {
    aClipRect->ToIntRect(&intClipRect);
    mGLContext->fScissor(intClipRect.x, intClipRect.y,
                         intClipRect.width, intClipRect.height);
  }

  if (aEffectChain.mEffects[EFFECT_SOLID_COLOR]) {
    EffectSolidColor* effectSolidColor =
      static_cast<EffectSolidColor*>(aEffectChain.mEffects[EFFECT_SOLID_COLOR]);

    gfx::Color color = effectSolidColor->mColor;

    /* Multiply color by the layer opacity, as the shader
     * ignores layer opacity and expects a final color to
     * write to the color buffer.  This saves a needless
     * multiply in the fragment shader.
     */
    gfx::Float opacity = aOpacity * color.a;
    color.r *= opacity;
    color.g *= opacity;
    color.b *= opacity;
    color.a = opacity;
    ShaderProgramOGL *program = GetProgram(gl::ColorLayerProgramType);
    program->Activate();
    program->SetLayerQuadRect(aRect);
    program->SetRenderColor(effectSolidColor->mColor);
    program->SetLayerTransform(aTransform);
    program->SetRenderOffset(nsIntPoint(0,0));
    BindAndDrawQuad(program);

  } else if (aEffectChain.mEffects[EFFECT_BGRA] || aEffectChain.mEffects[EFFECT_BGRX])  {
    RefPtr<TextureOGL> texture;
    bool premultiplied;
    gfxPattern::GraphicsFilter filter;
    ShaderProgramOGL *program;

    if (aEffectChain.mEffects[EFFECT_BGRA]) {
      EffectBGRA* effectBGRA =
        static_cast<EffectBGRA*>(aEffectChain.mEffects[EFFECT_BGRA]);
      texture = static_cast<TextureOGL*>(effectBGRA->mBGRATexture.get());
      premultiplied = effectBGRA->mPremultiplied;
      filter = gfx::ThebesFilter(effectBGRA->mFilter);
      program = GetProgram(gl::BGRALayerProgramType);
    } else {
      EffectBGRX* effectBGRX =
        static_cast<EffectBGRX*>(aEffectChain.mEffects[EFFECT_BGRX]);
      texture = static_cast<TextureOGL*>(effectBGRX->mBGRXTexture.get());
      premultiplied = effectBGRX->mPremultiplied;
      filter = gfx::ThebesFilter(effectBGRX->mFilter);
      program = GetProgram(gl::BGRXLayerProgramType);
    }

    if (!premultiplied) {
      mGLContext->fBlendFuncSeparate(LOCAL_GL_SRC_ALPHA, LOCAL_GL_ONE_MINUS_SRC_ALPHA,
                                     LOCAL_GL_ONE, LOCAL_GL_ONE);
    }

    mGLContext->fBindTexture(LOCAL_GL_TEXTURE_2D, texture->mTexture.mTextureHandle);
    mGLContext->ApplyFilterToBoundTexture(filter);

    program->Activate();
    program->SetTextureUnit(0);
    program->SetLayerOpacity(aOpacity);
    program->SetLayerTransform(aTransform);
    program->SetRenderOffset(nsIntPoint(0,0));
    program->SetLayerQuadRect(aRect);
    BindAndDrawQuadWithTextureRect(program, intSourceRect, texture->mSize);

    if (!premultiplied) {
      mGLContext->fBlendFuncSeparate(LOCAL_GL_ONE, LOCAL_GL_ONE_MINUS_SRC_ALPHA,
                                     LOCAL_GL_ONE, LOCAL_GL_ONE);
    }

  } else if (aEffectChain.mEffects[EFFECT_YCBCR]) {
    EffectYCbCr* effectYCbCr =
      static_cast<EffectYCbCr*>(aEffectChain.mEffects[EFFECT_YCBCR]);
    RefPtr<TextureOGL> textureY = static_cast<TextureOGL*>(effectYCbCr->mY.get());
    RefPtr<TextureOGL> textureCb = static_cast<TextureOGL*>(effectYCbCr->mCb.get());
    RefPtr<TextureOGL> textureCr = static_cast<TextureOGL*>(effectYCbCr->mCr.get());
    gfxPattern::GraphicsFilter filter = gfx::ThebesFilter(effectYCbCr->mFilter);

    mGLContext->fActiveTexture(LOCAL_GL_TEXTURE0);
    mGLContext->fBindTexture(LOCAL_GL_TEXTURE_2D, textureY->mTexture.mTextureHandle);
    mGLContext->ApplyFilterToBoundTexture(filter);
    mGLContext->fActiveTexture(LOCAL_GL_TEXTURE1);
    mGLContext->fBindTexture(LOCAL_GL_TEXTURE_2D, textureCb->mTexture.mTextureHandle);
    mGLContext->ApplyFilterToBoundTexture(filter);
    mGLContext->fActiveTexture(LOCAL_GL_TEXTURE2);
    mGLContext->fBindTexture(LOCAL_GL_TEXTURE_2D, textureCr->mTexture.mTextureHandle);
    mGLContext->ApplyFilterToBoundTexture(filter);

    ShaderProgramOGL *program = GetProgram(YCbCrLayerProgramType);

    program->Activate();
    program->SetYCbCrTextureUnits(0, 1, 2);
    program->SetLayerOpacity(aOpacity);
    program->SetLayerTransform(aTransform);
    program->SetRenderOffset(nsIntPoint(0,0));
    program->SetLayerQuadRect(aRect);
    BindAndDrawQuadWithTextureRect(program, intSourceRect, textureY->mSize);

  } else if (aEffectChain.mEffects[EFFECT_COMPONENT_ALPHA]) {
    EffectComponentAlpha* effectComponentAlpha =
      static_cast<EffectComponentAlpha*>(aEffectChain.mEffects[EFFECT_COMPONENT_ALPHA]);
    RefPtr<TextureOGL> textureOnWhite =
      static_cast<TextureOGL*>(effectComponentAlpha->mOnWhite.get());
    RefPtr<TextureOGL> textureOnBlack =
      static_cast<TextureOGL*>(effectComponentAlpha->mOnBlack.get());

    for (PRInt32 pass = 1; pass <=2; ++pass) {
      ShaderProgramOGL* program;
      if (pass == 1) {
        program = GetProgram(gl::ComponentAlphaPass1ProgramType);
        gl()->fBlendFuncSeparate(LOCAL_GL_ZERO, LOCAL_GL_ONE_MINUS_SRC_COLOR,
                                 LOCAL_GL_ONE, LOCAL_GL_ONE);
      } else {
        program = GetProgram(gl::ComponentAlphaPass2ProgramType);
        gl()->fBlendFuncSeparate(LOCAL_GL_ONE, LOCAL_GL_ONE,
                                 LOCAL_GL_ONE, LOCAL_GL_ONE);
      }

      mGLContext->fActiveTexture(LOCAL_GL_TEXTURE0);
      mGLContext->fBindTexture(LOCAL_GL_TEXTURE_2D, textureOnBlack->mTexture.mTextureHandle);
      mGLContext->fActiveTexture(LOCAL_GL_TEXTURE1);
      mGLContext->fBindTexture(LOCAL_GL_TEXTURE_2D, textureOnWhite->mTexture.mTextureHandle);

      program->Activate();
      program->SetBlackTextureUnit(0);
      program->SetWhiteTextureUnit(1);
      program->SetLayerOpacity(aOpacity);
      program->SetLayerTransform(aTransform);
      program->SetRenderOffset(nsIntPoint(0,0));
      program->SetLayerQuadRect(aRect);

      BindAndDrawQuadWithTextureRect(program, intSourceRect, textureOnBlack->mSize);

      mGLContext->fBlendFuncSeparate(LOCAL_GL_ONE, LOCAL_GL_ONE_MINUS_SRC_ALPHA,
                                     LOCAL_GL_ONE, LOCAL_GL_ONE);
    }
  }

  // TODO: Handle EFFECT_MASK in all cases above.
}

} /* layers */
} /* mozilla */
